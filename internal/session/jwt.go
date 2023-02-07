package session

import (
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

var jwtSigningMethod = jwt.SigningMethodHS256

// Aliasing it so we can use it in the struct literal for composition
type jwtRegisteredClaims = jwt.RegisteredClaims

type jwtClaims struct {
	SessionData
	jwtRegisteredClaims
}

type JWTSessionHandler struct {
	Secret       []byte
	CookieName   string
	CookieSecure bool
	Lifetime     time.Duration
}

func (s *JWTSessionHandler) Start(c echo.Context, data SessionData) error {
	sessExpiryTime := time.Now().Add(s.Lifetime * time.Second)

	// We've now verified our user
	sessClaims := &jwtClaims{
		SessionData: data,
		jwtRegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(sessExpiryTime),
		},
	}

	sessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, sessClaims)

	signedSessToken, err := sessToken.SignedString(s.Secret)
	if err != nil {
		return fmt.Errorf("couldn't sign session JWT: %v", err)
	}

	c.SetCookie(&http.Cookie{
		Name:     s.CookieName,
		Value:    signedSessToken,
		Secure:   s.CookieSecure,
		HttpOnly: true,
		Expires:  sessExpiryTime,
	})

	return nil
}

func (s *JWTSessionHandler) Destroy(c echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:    s.CookieName,
		Value:   "",
		Expires: time.Unix(0, 0),
	})
	return nil
}

func (s *JWTSessionHandler) GetSessionData(c echo.Context) (*SessionData, error) {
	authCookie, err := c.Cookie(s.CookieName)
	if err != nil || authCookie.Value == "" {
		return nil, ErrInvalidSession
	}

	decoder := jwt.NewParser(jwt.WithValidMethods([]string{jwtSigningMethod.Alg()}))

	claims := new(jwtClaims)

	token, err := decoder.ParseWithClaims(authCookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return s.Secret, nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidSession
	}

	return &claims.SessionData, nil
}
