package webserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lachlan2k/oh-id-see/internal/config"
	"golang.org/x/oauth2"
)

type oidcUtils struct {
	ctx      context.Context
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
}

func makeOIDCUtils(conf config.Config) (*oidcUtils, error) {
	utils := &oidcUtils{}
	utils.ctx = context.Background()

	shouldOverrideDiscovery := conf.OIDC.IssuerDiscoveryOverrideURL != ""

	var err error

	if shouldOverrideDiscovery {
		utils.ctx = oidc.InsecureIssuerURLContext(utils.ctx, conf.OIDC.IssuerURL)
		utils.provider, err = oidc.NewProvider(utils.ctx, conf.OIDC.IssuerDiscoveryOverrideURL)
	} else {
		utils.provider, err = oidc.NewProvider(utils.ctx, conf.OIDC.IssuerURL)
	}

	if err != nil {
		return nil, err
	}

	endpoint := utils.provider.Endpoint()

	if shouldOverrideDiscovery {
		endpoint.AuthURL = strings.Replace(endpoint.AuthURL, conf.OIDC.IssuerDiscoveryOverrideURL, conf.OIDC.IssuerURL, 1)
	}

	utils.config = &oauth2.Config{
		ClientID:     conf.OIDC.ClientID,
		ClientSecret: conf.OIDC.ClientSecret,
		RedirectURL:  conf.OIDC.RedirectURL,

		Endpoint: endpoint,
		Scopes:   []string{oidc.ScopeOpenID, "email", "profile"},
	}

	utils.verifier = utils.provider.Verifier(&oidc.Config{ClientID: conf.OIDC.ClientID})

	return utils, nil
}

type oauthState struct {
	Nonce    string
	Redirect string
}

var jwtSigningMethod = jwt.SigningMethodHS256

type jwtClaims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

func Listen(conf config.Config) {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	oidcUtils, err := makeOIDCUtils(conf)

	emailAllowlistEnabled := len(conf.AccessControl.EmailAllowlist) > 0
	aclsEnabled := !conf.AccessControl.DisableACLRules

	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	e.GET("/login", func(c echo.Context) error {
		buff := make([]byte, 16)
		rand.Read(buff)
		nonceStr := base64.RawURLEncoding.EncodeToString(buff)
		state := oauthState{
			Nonce:    nonceStr,
			Redirect: c.QueryParam("redir"),
		}

		stateBuff, err := json.Marshal(state)
		if err != nil {
			e.Logger.Errorf("Failed to marshal state for oauth: %v", err)
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
	})

	e.GET("/callback", func(c echo.Context) error {
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
			e.Logger.Warnf("Couldn't perform oauth2 exchange, code: %s, err: %v", code, err)
			return c.String(http.StatusInternalServerError, "Failed perform oauth2 exchange: provided code was likely invalid")
		}

		rawToken, ok := token.Extra("id_token").(string)
		if !ok {
			e.Logger.Warnf("Couldn't cast id_token to string, token is %v", token.AccessToken)
			return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
		}

		idToken, err := oidcUtils.verifier.Verify(oidcUtils.ctx, rawToken)
		if err != nil {
			e.Logger.Warnf("id_token failed verification: token: %s, err: %v", rawToken, err)
			return c.String(http.StatusInternalServerError, "Server received invalid oauth2 access token")
		}

		claims := map[string]interface{}{}
		err = idToken.Claims(&claims)
		if err != nil {
			e.Logger.Warnf("Couldn't extract claims from ID token, token: %s, err: %v", rawToken, err)
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
			e.Logger.Warnf("Couldn't sign session JWT: %v", err)
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
	})

	e.GET("/auth", func(c echo.Context) error {
		authCookie, err := c.Cookie(conf.Cookie.Name)
		if err != nil || authCookie.Value == "" {
			return c.String(http.StatusForbidden, "")
		}

		jwtStr := authCookie.Value

		var authClaims jwtClaims

		token, err := jwt.ParseWithClaims(jwtStr, &authClaims, func(token *jwt.Token) (interface{}, error) {
			signingMethod, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok || signingMethod.Alg() != jwtSigningMethod.Alg() {
				return nil, errors.New("invalid signing method found on jwt")
			}

			return []byte(conf.Cookie.Secret), nil
		})

		if err != nil {
			e.Logger.Warnf("Received invalid JWT: %v, err: %v", jwtStr, err)
			return c.String(http.StatusForbidden, "")
		}

		if !token.Valid {
			e.Logger.Warnf("Recieved JWT with invalid signature: %v, err: %v", jwtStr, err)
			return c.String(http.StatusForbidden, "")
		}

		// Check access control
		if emailAllowlistEnabled {
			found := false
			for _, emailToCheck := range conf.AccessControl.EmailAllowlist {
				if emailToCheck == authClaims.Email {
					found = true
					break
				}
			}

			if !found {
				e.Logger.Warnf("User was successfully auth'd (%s), but their email wasn't in the allow list", authClaims.Email)
				return c.String(http.StatusForbidden, "")
			}
		}

		hostName := c.Request().Host

		// TODO: should we do role merging when the user first auths?
		// TBH, I prefer this because it means the ACLs can be changed, the program restarted, and an existing jwt doesn't carry over
		allOfUsersRoles := make([]string, len(authClaims.Roles))
		copy(allOfUsersRoles, authClaims.Roles)

		if roleListForUser, ok := conf.AccessControl.RoleMapping[authClaims.Email]; ok {
			allOfUsersRoles = append(allOfUsersRoles, roleListForUser...)
		}

		// TODO: more efficient solution
		if aclsEnabled {
			for _, roleName := range allOfUsersRoles {
				if roleACL, ok := conf.AccessControl.ACLs[roleName]; ok {
					// TODO: regex/wildcard?
					found := false
					for _, hostToCheck := range roleACL {
						if hostName == hostToCheck {
							found = true
							break
						}
					}

					if !found {
						e.Logger.Warnf("User (%s) tried to access a hostname they are not authorised to accces (%s)", authClaims.Email, hostName)
						return c.String(http.StatusForbidden, "")
					}
				}
			}
		}

		// We passed all of our ACL checks, allow user
		var res struct {
			Email string   `json:"email"`
			Roles []string `json:"roles"`
		}

		res.Email = authClaims.Email
		res.Roles = authClaims.Roles

		return c.JSON(http.StatusOK, res)
	})

	authRoute := e.Group("/auth")

	authRoute.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte(conf.Cookie.Secret),
	}))

	authRoute.GET("", func(c echo.Context) error {
		return c.String(http.StatusOK, "Logged in")
	})

	err = e.Start(fmt.Sprintf(":%d", conf.ListenPort))
	e.Logger.Fatal(err)
}
