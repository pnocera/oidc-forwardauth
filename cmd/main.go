package main

import (
	"fmt"
	"net/http"

	internal "github.com/pnocera/oidc-forwardauth/internal"
)

// Main
func main() {
	// Parse options
	config := internal.NewConfig()

	// Setup logger
	log := internal.NewDefaultLogger(config)

	// Build server
	server := internal.NewServer(config)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port())
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port()), nil))
}
