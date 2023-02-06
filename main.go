package main

import (
	"flag"

	"github.com/lachlan2k/id-sea/internal/config"
	"github.com/lachlan2k/id-sea/internal/webserver"
)

func main() {
	confPath := flag.String("config", "config.toml", "Path to config file")
	flag.Parse()

	server := webserver.New()
	logger := server.Logger()

	conf, err := config.LoadFromTomlFileAndValidate(*confPath)
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	server.Run(conf)
}
