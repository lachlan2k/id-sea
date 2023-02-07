package main

import (
	"flag"
	"log"

	"github.com/lachlan2k/id-sea/internal/config"
	"github.com/lachlan2k/id-sea/internal/webserver"
)

func main() {
	confPath := flag.String("config", "config.toml", "Path to config file")
	flag.Parse()

	conf, err := config.LoadFromTomlFileAndValidate(*confPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	server := webserver.New(conf)

	server.Run(conf)
}
