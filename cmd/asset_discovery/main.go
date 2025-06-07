package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/handlers/http"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

var configPath = flag.String("config", "config.json", "service configuration file")

func main() {
	flag.Parse()
	if v := os.Getenv("CONFIG_PATH"); len(v) > 0 {
		*configPath = v
	}
	config := config.MustReadConfig(*configPath)
	AppContainer := app.NewMustApp(config)

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the scheduler
	log.Println("Starting scheduler...")
	AppContainer.StartScheduler()

	// Handle shutdown signals in a separate goroutine
	go func() {
		sig := <-signalChan
		log.Printf("Received signal: %v. Shutting down...", sig)

		// Stop the scheduler
		log.Println("Stopping scheduler...")
		AppContainer.StopScheduler()

		// Allow a clean exit if the HTTP server is still running
		os.Exit(0)
	}()

	// Start the HTTP server (this will block until the server exits)
	log.Fatal(http.Run(AppContainer, config.Server))
}
