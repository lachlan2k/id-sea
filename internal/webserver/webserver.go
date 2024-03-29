package webserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/lachlan2k/id-sea/internal/config"
	"github.com/lachlan2k/id-sea/internal/session"
)

type Webserver struct {
	e              *echo.Echo
	conf           *config.Config
	sessionHandler session.SessionHandler
	oidcUtils      oidcUtils
}

func New(conf *config.Config) *Webserver {
	e := echo.New()

	sessionHandler := &session.JWTSessionHandler{
		Secret:       []byte(conf.Session.Cookie.Secret),
		CookieName:   conf.Session.Cookie.Name,
		CookieDomain: conf.Session.Cookie.Domain,
		CookieSecure: conf.Session.Cookie.Secure,
		Lifetime:     time.Duration(conf.Session.Lifetime),
	}

	oidcUtils, err := makeOIDCUtils(conf)
	if err != nil {
		e.Logger.Fatal(err)
	}

	return &Webserver{
		e:              e,
		conf:           conf,
		sessionHandler: sessionHandler,
		oidcUtils:      *oidcUtils,
	}
}

func (w *Webserver) Logger() echo.Logger {
	return w.e.Logger
}

func (w *Webserver) Run(conf *config.Config) {
	e := w.e

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	e.GET("/login", w.loginRouteHandler)
	e.GET("/logout", w.logoutRouteHandler)
	e.GET("/callback", w.callbackRouteHandler)
	e.GET("/info", w.authInfoRouteHandler)
	e.GET("/verify", w.verifyAuthRouteHandler)

	err := w.e.Start(fmt.Sprintf(":%d", conf.ListenPort))
	w.e.Logger.Fatal(err)
}
