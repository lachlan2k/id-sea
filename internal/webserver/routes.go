package webserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/id-sea/internal/accesscontrol"
	"github.com/lachlan2k/id-sea/internal/session"
	"github.com/lachlan2k/id-sea/internal/utils"
)

type AuthInfoRes struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

func (w *Webserver) loginRouteHandler(c echo.Context) error {
	logger := c.Echo().Logger

	nonceBuff := make([]byte, 16)
	_, err := rand.Read(nonceBuff)
	if err != nil {
		logger.Errorf("Failed to generate random material for oauth nonce: %v", err)
		return c.String(http.StatusInternalServerError, "Something went wrong")
	}

	nonceStr := base64.RawURLEncoding.EncodeToString(nonceBuff)
	state := oauthState{
		Nonce:    nonceStr,
		Redirect: c.QueryParam("redir"),
	}

	if state.Redirect == "" {
		state.Redirect = "/auth"
	}

	stateBuff, err := json.Marshal(state)
	if err != nil {
		logger.Errorf("Failed to marshal state for oauth: %v", err)
		return c.String(http.StatusInternalServerError, "Something went wrong")
	}

	stateStr := string(stateBuff)

	c.SetCookie(&http.Cookie{
		Name:     nonceCookieName,
		Value:    nonceStr,
		Expires:  time.Now().Add(5 * time.Minute),
		Secure:   w.conf.Session.Cookie.Secure,
		Path:     "/",
		HttpOnly: true,
	})

	return c.Redirect(http.StatusFound, w.oidcUtils.config.AuthCodeURL(stateStr))
}

func (w *Webserver) logoutRouteHandler(c echo.Context) error {
	w.sessionHandler.Destroy(c)
	return c.String(http.StatusOK, "")
}

func (w *Webserver) callbackRouteHandler(c echo.Context) error {
	logger := c.Echo().Logger

	var state oauthState
	err := json.Unmarshal([]byte(c.QueryParam("state")), &state)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid state")
	}

	cookieNonce, err := c.Cookie(nonceCookieName)
	if err != nil || cookieNonce.Value == "" {
		return c.String(http.StatusBadRequest, "State cookie wasn't found: request likely expired")
	}

	if cookieNonce.Value != state.Nonce {
		return c.String(http.StatusBadRequest, "State nonce mismatch")
	}

	code := c.QueryParam("code")
	if code == "" {
		return c.String(http.StatusBadRequest, "No code was provided")
	}

	token, err := w.oidcUtils.config.Exchange(w.oidcUtils.ctx, code)
	if err != nil {
		logger.Printf("Couldn't perform oauth2 exchange, code: %s, err: %v", code, err)
		return c.String(http.StatusInternalServerError, "Failed perform oauth2 exchange: provided code was likely invalid")
	}

	rawToken, ok := token.Extra("id_token").(string)
	if !ok {
		logger.Printf("Couldn't cast id_token to string, token is %v", token.AccessToken)
		return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
	}

	idToken, err := w.oidcUtils.verifier.Verify(w.oidcUtils.ctx, rawToken)
	if err != nil {
		logger.Printf("id_token failed verification: token: %s, err: %v", rawToken, err)
		return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
	}

	claims := map[string]any{}
	err = idToken.Claims(&claims)
	if err != nil {
		logger.Printf("Couldn't extract claims from ID token, token: %s, err: %v", rawToken, err)
		return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
	}

	roles, err := extractRolesFromClaim(w.conf, claims)
	if err != nil {
		logger.Printf("Couldn't extract roles from claims, token: %s, err: %v", rawToken, err)
		return c.String(http.StatusInternalServerError, "Server received token with invalid claims")
	}

	email, ok := claims["email"].(string)
	if !ok && email == "" {
		logger.Printf("Couldn't extract email from token claims (%v)", w.conf.OIDC.RoleClaimName, claims)
		return c.String(http.StatusInternalServerError, "Server received token with invalid claims")
	}

	if !w.conf.AccessControl.AllowAllEmails {
		if !utils.TestStringAgainstSliceMatchers(w.conf.AccessControl.EmailAllowlist, email) {
			logger.Printf("Denied authentication attempt for %s, as their email wasn't in the allow list", email)
			return c.String(http.StatusForbidden, "Forbidden")
		}
	}

	err = w.sessionHandler.Start(c, session.SessionData{
		Email: email,
		Roles: roles,
	})
	if err != nil {
		logger.Printf("Couldn't start user's session: %v", err)
		w.sessionHandler.Destroy(c) // Might as well try and clean up anyway, doesn't matter if it fails
		return c.String(http.StatusInternalServerError, "Couldn't log you in")
	}

	if accesscontrol.VerifyRedirectURL(w.conf, state.Redirect) {
		return c.Redirect(http.StatusFound, state.Redirect)
	}

	return c.JSON(http.StatusOK, AuthInfoRes{
		Email: email,
		Roles: utils.GetAllRolesForUser(w.conf, email, roles),
	})
}

type unauthorizedResponse struct {
	Error string `json:"error"`
}

func (w *Webserver) authInfoRouteHandler(c echo.Context) error {
	logger := c.Echo().Logger

	sessionData, err := w.sessionHandler.GetSessionData(c)
	if err != nil {
		if err != session.ErrInvalidSession {
			logger.Printf("unexpected error occured getting session data: %v", err)
		}
		return c.JSON(http.StatusForbidden, unauthorizedResponse{
			Error: "Unauthorized",
		})
	}

	return c.JSON(http.StatusOK, AuthInfoRes{
		Email: sessionData.Email,
		Roles: utils.GetAllRolesForUser(w.conf, sessionData.Email, sessionData.Roles),
	})
}

func (w *Webserver) verifyAuthRouteHandler(c echo.Context) error {
	logger := c.Echo().Logger

	sessionData, err := w.sessionHandler.GetSessionData(c)
	if err != nil {
		if err == session.ErrInvalidSession {
			return c.Redirect(http.StatusFound, w.conf.BaseURL+"/login?redir="+c.QueryParam("redir"))
		}

		logger.Printf("unexpected error occured getting session data: %v", err)

		return c.JSON(http.StatusForbidden, unauthorizedResponse{
			Error: "Unauthorized",
		})
	}

	err = accesscontrol.CheckAccess(w.conf, sessionData.Email, utils.GetAllRolesForUser(w.conf, sessionData.Email, sessionData.Roles), c.Request().Host)
	if err != nil {
		logger.Printf(err.Error())
		return c.JSON(http.StatusForbidden, unauthorizedResponse{
			Error: fmt.Sprintf("%s is not allowed to access %s", sessionData.Email, c.Request().Host),
		})
	}

	// We passed all of our ACL checks, allow user
	return c.JSON(http.StatusOK, AuthInfoRes{
		Email: sessionData.Email,
		Roles: utils.GetAllRolesForUser(w.conf, sessionData.Email, sessionData.Roles),
	})
}
