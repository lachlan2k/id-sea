package webserver

import (
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/lachlan2k/id-sea/internal/config"
)

var jwtSigningMethod = jwt.SigningMethodHS256

type jwtClaims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

func validateJWT(conf *config.Config, c echo.Context) (*jwtClaims, error) {
	authCookie, err := c.Cookie(conf.Cookie.Name)
	if err != nil || authCookie.Value == "" {
		return nil, fmt.Errorf("cookie was missing or empty: %v", err)
	}

	jwtStr := authCookie.Value

	authClaims := new(jwtClaims)

	token, err := jwt.ParseWithClaims(jwtStr, authClaims, func(token *jwt.Token) (interface{}, error) {
		signingMethod, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok || signingMethod.Alg() != jwtSigningMethod.Alg() {
			return nil, errors.New("invalid signing method found on jwt")
		}

		return []byte(conf.Cookie.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("received invalid JWT: %v, err: %v", jwtStr, err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("recieved JWT with invalid signature: %v, err: %v", jwtStr, err)
	}

	return authClaims, nil
}
