package webserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/oh-id-see/internal/accesscontrol"
	"github.com/lachlan2k/oh-id-see/internal/config"
)

func loginRouteHandler(c echo.Context, oidcUtils *oidcUtils, conf *config.Config) error {
	logger := c.Echo().Logger

	nonceBuff := make([]byte, 16)
	rand.Read(nonceBuff)
	nonceStr := base64.RawURLEncoding.EncodeToString(nonceBuff)
	state := oauthState{
		Nonce:    nonceStr,
		Redirect: c.QueryParam("redir"),
	}

	stateBuff, err := json.Marshal(state)
	if err != nil {
		logger.Errorf("Failed to marshal state for oauth: %v", err)
		return c.String(http.StatusInternalServerError, "Something went wrong")
	}

	stateStr := string(stateBuff)

	c.SetCookie(&http.Cookie{
		Name:     "_oauth_state_nonce",
		Value:    nonceStr,
		Expires:  time.Now().Add(5 * time.Minute),
		Secure:   conf.Cookie.Secure,
		HttpOnly: true,
	})

	return c.Redirect(http.StatusFound, oidcUtils.config.AuthCodeURL(stateStr))
}

func callbackRouteHandler(c echo.Context, oidcUtils *oidcUtils, conf *config.Config) error {
	logger := c.Echo().Logger

	var state oauthState
	err := json.Unmarshal([]byte(c.QueryParam("state")), &state)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid state")
	}

	cookieNonce, err := c.Cookie("_oauth_state_nonce")
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

	token, err := oidcUtils.config.Exchange(oidcUtils.ctx, code)
	if err != nil {
		logger.Warnf("Couldn't perform oauth2 exchange, code: %s, err: %v", code, err)
		return c.String(http.StatusInternalServerError, "Failed perform oauth2 exchange: provided code was likely invalid")
	}

	rawToken, ok := token.Extra("id_token").(string)
	if !ok {
		logger.Warnf("Couldn't cast id_token to string, token is %v", token.AccessToken)
		return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
	}

	idToken, err := oidcUtils.verifier.Verify(oidcUtils.ctx, rawToken)
	if err != nil {
		logger.Warnf("id_token failed verification: token: %s, err: %v", rawToken, err)
		return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
	}

	claims := map[string]interface{}{}
	err = idToken.Claims(&claims)
	if err != nil {
		logger.Warnf("Couldn't extract claims from ID token, token: %s, err: %v", rawToken, err)
		return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
	}

	sessExpiryTime := time.Now().Add(time.Duration(conf.Cookie.MaxAge) * time.Second)

	// We've now su verified our user
	sessClaims := &jwtClaims{
		"todo",
		[]string{"todo"},
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(sessExpiryTime),
		},
	}

	sessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, sessClaims)

	signedSessToken, err := sessToken.SignedString([]byte(conf.Cookie.Secret))
	if err != nil {
		logger.Warnf("Couldn't sign session JWT: %v", err)
		return c.String(http.StatusInternalServerError, "Failed to start session")
	}

	c.SetCookie(&http.Cookie{
		Name:     conf.Cookie.Name,
		Value:    signedSessToken,
		Secure:   conf.Cookie.Secure,
		HttpOnly: true,
		Expires:  sessExpiryTime,
	})

	// TODO: verify redirect URL
	return c.Redirect(http.StatusFound, state.Redirect)
}

func authRouteHandler(c echo.Context, conf *config.Config) error {
	logger := c.Echo().Logger

	authClaims, err := validateJWT(conf, c)
	if err != nil {
		logger.Warnf(err.Error())
		return c.String(http.StatusForbidden, "")
	}

	err = accesscontrol.CheckAccess(conf, authClaims.Email, authClaims.Roles, c.Request().Host)
	if err != nil {
		logger.Warnf(err.Error())
		return c.String(http.StatusForbidden, "")
	}

	// We passed all of our ACL checks, allow user
	var res struct {
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	}

	res.Email = authClaims.Email
	res.Roles = authClaims.Roles

	return c.JSON(http.StatusOK, res)
}
