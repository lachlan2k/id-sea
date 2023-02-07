package session

import (
	"errors"

	"github.com/labstack/echo/v4"
)

type Token = string

type SessionData struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

type SessionHandler interface {
	Start(echo.Context, SessionData) error
	Destroy(echo.Context) error
	GetSessionData(echo.Context) (*SessionData, error)
}

var ErrInvalidSession = errors.New("session token was invalid")
