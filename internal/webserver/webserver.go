package webserver

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/labstack/echo/v4/middleware"
	"github.com/lachlan2k/oh-id-see/internal/config"
)

func Listen(conf *config.Config) {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	oidcUtils, err := makeOIDCUtils(conf)

	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	e.GET("/login", func(c echo.Context) error {
		return loginRouteHandler(c, oidcUtils, conf)
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
