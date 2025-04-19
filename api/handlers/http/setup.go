package http

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2"

	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

func Run(appContainer app.AppContainer, cfg config.ServerConfig) error {
	router := fiber.New(fiber.Config{
		AppName: "APK Asset Discovery",
	})
	router.Use(helmet.New())
	router.Use(TraceMiddleware())
	router.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path} TraceID: ${locals:traceID}\n",
		Output: os.Stdout,
	}))

	router.Get("/", func(c *fiber.Ctx) error {
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		return c.SendString("Secure HTTPS server")
	})

	api := router.Group("/api/v1", setUserContext)

	registerAuthAPI(appContainer, cfg, api)

	registerScannerAPI(appContainer, api.Group("/scanners"))
	registerScanJobAPI(appContainer, api.Group("/scanjobs"))

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Set minimum TLS version (TLS 1.2)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true, // Server prefers its cipher suites
	}

	router.Server().TLSConfig = tlsConfig
	return router.ListenTLS(fmt.Sprintf(":%d", cfg.HttpPort), cfg.Cert, cfg.Key)

	// return router.Listen(fmt.Sprintf(":%d", cfg.HttpPort))

}

func registerAuthAPI(appContainer app.AppContainer, cfg config.ServerConfig, router fiber.Router) {
	userSvcGetter := userServiceGetter(appContainer, cfg)
	router.Post("/sign-up", setTransaction(appContainer.DB()), SignUp(userSvcGetter))
	router.Post("/sign-in", setTransaction(appContainer.DB()), SignIn(userSvcGetter, cfg))
	router.Post("/sign-out", setTransaction(appContainer.DB()), SignOut(userSvcGetter))
}

func registerScannerAPI(appContainer app.AppContainer, router fiber.Router) {
	scannerSvcGetter := scannerServiceGetter(appContainer)
	router.Post("/", setTransaction(appContainer.DB()), CreateScanner(scannerSvcGetter))
	router.Get("/:id", GetScanner(scannerSvcGetter))
	router.Get("/", ListScanners(scannerSvcGetter))
	router.Put("/:id", setTransaction(appContainer.DB()), UpdateScanner(scannerSvcGetter))
	router.Delete("/:id", setTransaction(appContainer.DB()), DeleteScanner(scannerSvcGetter))

	router.Post("/batch-delete", setTransaction(appContainer.DB()), DeleteScanners(scannerSvcGetter))
	router.Post("/batch-enabled", setTransaction(appContainer.DB()), BatchUpdateScannersEnabled(scannerSvcGetter))

	// Add the new scan now endpoint
	router.Post("/:id/run", RunScanNow(scannerSvcGetter))
}

// Register the scan job API endpoints
func registerScanJobAPI(appContainer app.AppContainer, router fiber.Router) {
	scannerSvcGetter := scannerServiceGetter(appContainer)

	// Route to cancel a running scan job
	router.Post("/cancel/:id", CancelScanJob(scannerSvcGetter))

	// You may want to add additional routes here for listing scan jobs, etc.
}
