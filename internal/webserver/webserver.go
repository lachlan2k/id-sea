package webserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/labstack/echo/v4/middleware"
	"github.com/lachlan2k/id-sea/internal/config"
)

type Webserver struct {
	e *echo.Echo
}

func New() *Webserver {
	return &Webserver{
		e: echo.New(),
	}
}

func (w *Webserver) Logger() echo.Logger {
	return w.e.Logger
}

func (w *Webserver) Run(conf *config.Config) {
	e := w.e

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	oidcUtils, err := makeOIDCUtils(conf)

	if err != nil {
		e.Logger.Fatal(err)
	}

	e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	e.GET("/login", func(c echo.Context) error {
		return loginRouteHandler(c, oidcUtils, conf)
	})

	e.GET("/logout", func(c echo.Context) error {
		c.SetCookie(&http.Cookie{
			Name:    nonceCookieName,
			Value:   "",
			Expires: time.Unix(0, 0),
		})
		return c.String(http.StatusOK, "Logged out")
	})

	e.GET("/callback", func(c echo.Context) error {
		return callbackRouteHandler(c, oidcUtils, conf)
	})

	e.GET("/auth", func(c echo.Context) error {
		return authRouteHandler(c, conf)
	})

	err = e.Start(fmt.Sprintf(":%d", conf.ListenPort))
	e.Logger.Fatal(err)
}
