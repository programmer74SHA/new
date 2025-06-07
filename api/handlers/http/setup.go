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
	registerAssetAPI(appContainer, api)
	registerScannerAPI(appContainer, api.Group("/scanners"))

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

	router.Post("/delete", setTransaction(appContainer.DB()), DeleteScanners(scannerSvcGetter))
	router.Post("/status", setTransaction(appContainer.DB()), UpdateScannerStatus(scannerSvcGetter))

	router.Post("/:id/run", RunScanNow(scannerSvcGetter))
	router.Post("/cancel/:id", CancelScanJob(scannerSvcGetter))
}

func registerAssetAPI(appContainer app.AppContainer, router fiber.Router) {
	assetSvcGetter := assetServiceGetter(appContainer)
	scanJobSvcGetter := scanJobServiceGetter(appContainer)

	// Create asset routes group
	assets := router.Group("/assets")

	// Register endpoints
	assets.Get("/", GetAssets(assetSvcGetter))
	assets.Get("/:id", GetAssetByID(assetSvcGetter))
	assets.Get("/os/names", GetDistinctOSNames(assetSvcGetter))
	assets.Post("/", CreateAsset(assetSvcGetter))
	assets.Put("/:id", UpdateAsset(assetSvcGetter))
	assets.Delete("/:id", DeleteAsset(assetSvcGetter))
	assets.Delete("/", DeleteAssets(assetSvcGetter))

	// Export endpoints
	assets.Post("/export/csv", ExportAssets(assetSvcGetter))

	// Create scan job routes group
	scanJobs := router.Group("/scan-jobs")

	// Register endpoints
	scanJobs.Get("/", GetScanJobs(scanJobSvcGetter))
	scanJobs.Get("/:id", GetScanJobByID(scanJobSvcGetter))
	scanJobs.Post("/diff", DiffJobs(scanJobSvcGetter))
	scanJobs.Post("/diff/export/csv", ExportJobDiff(scanJobSvcGetter))

}
