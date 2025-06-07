package app

import (
	"context"
	"log"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler"
	schedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/user"
	userDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/domain"
	userPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/mysql"
	"gorm.io/gorm"
)

type app struct {
	db                *gorm.DB
	cfg               config.Config
	assetService      assetPort.Service
	userService       userPort.Service
	scannerService    scannerPort.Service
	schedulerService  schedulerPort.Service
	schedulerRunner   *scheduler.SchedulerRunner
	nmapScanner       *scanner.NmapRunner
	vcenterScanner    *scanner.VCenterRunner
	domainScanner     *scanner.DomainRunner
	firewallScanner   *scanner.FirewallRunner // Add firewall scanner
	apiScannerService *service.ScannerService
	scanJobService    scanJobPort.Service
}

func (a *app) AssetService(ctx context.Context) assetPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.assetService == nil {
			a.assetService = a.assetServiceWithDB(a.db)
		}
		return a.assetService
	}
	return a.assetServiceWithDB(db)
}

func (a *app) assetServiceWithDB(db *gorm.DB) assetPort.Service {
	return asset.NewAssetService(storage.NewAssetRepo(db))
}

func (a *app) DB() *gorm.DB {
	return a.db
}

func (a *app) userServiceWithDB(db *gorm.DB) userPort.Service {
	return user.NewUserService(storage.NewUserRepo(db))
}

func (a *app) UserService(ctx context.Context) userPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.userService == nil {
			a.userService = a.userServiceWithDB(a.db)
		}
		return a.userService
	}
	return a.userServiceWithDB(db)
}

func (a *app) scanJobServiceWithDB(db *gorm.DB) scanJobPort.Service {
	return scanjob.NewScanJobService(
		storage.NewScanJobRepo(db),
		a.assetServiceWithDB(db),
	)
}

func (a *app) ScanJobService(ctx context.Context) scanJobPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.scanJobService == nil {
			a.scanJobService = a.scanJobServiceWithDB(a.db)
		}
		return a.scanJobService
	}
	return a.scanJobServiceWithDB(db)
}

func (a *app) Config() config.Config {
	return a.cfg
}

func (a *app) setDB() error {
	db, err := mysql.NewMysqlConnection(mysql.DBConnOptions{
		Host:     a.cfg.DB.Host,
		Port:     a.cfg.DB.Port,
		Username: a.cfg.DB.Username,
		Password: a.cfg.DB.Password,
		Database: a.cfg.DB.Database,
	})
	if err != nil {
		return err
	}
	mysql.GormMigrations(db)
	mysql.SeedData(db, userDomain.HashPassword)
	a.db = db
	return nil
}

func NewApp(cfg config.Config) (AppContainer, error) {
	a := &app{
		cfg: cfg,
	}
	if err := a.setDB(); err != nil {
		return nil, err
	}

	// Initialize asset repository and service
	assetRepo := storage.NewAssetRepo(a.db)
	a.assetService = asset.NewAssetService(assetRepo)

	// Initialize scanners - use the asset repo directly
	a.nmapScanner = scanner.NewNmapRunner(assetRepo)
	a.vcenterScanner = scanner.NewVCenterRunner(assetRepo)
	a.domainScanner = scanner.NewDomainRunner(assetRepo)
	a.firewallScanner = scanner.NewFirewallRunner(assetRepo) // Initialize firewall scanner

	// Log scanner initialization to help with debugging
	if a.nmapScanner == nil {
		log.Printf("Warning: NmapScanner was not initialized properly")
	} else {
		log.Printf("NmapScanner initialized successfully")
	}
	if a.vcenterScanner == nil {
		log.Printf("Warning: VCenterScanner was not initialized properly")
	} else {
		log.Printf("VCenterScanner initialized successfully")
	}
	if a.domainScanner == nil {
		log.Printf("Warning: DomainScanner was not initialized properly")
	} else {
		log.Printf("DomainScanner initialized successfully")
	}
	if a.firewallScanner == nil {
		log.Printf("Warning: FirewallScanner was not initialized properly")
	} else {
		log.Printf("FirewallScanner initialized successfully")
	}

	// Initialize scanner service (internal domain layer)
	scannerRepo := storage.NewScannerRepo(a.db)
	a.scannerService = scanner.NewScannerService(scannerRepo)

	// Initialize scheduler service with all scanners including firewall
	schedulerRepo := storage.NewSchedulerRepo(a.db)
	a.schedulerService = scheduler.NewSchedulerService(
		schedulerRepo,
		a.scannerService,
		a.nmapScanner,
		a.vcenterScanner,
		a.domainScanner,
		a.firewallScanner,
	)

	// Initialize API scanner service (external API layer)
	a.apiScannerService = service.NewScannerService(a.scannerService)

	// Connect the API scanner service to the scheduler service for cancellation
	a.apiScannerService.SetSchedulerService(a.schedulerService)

	// Create the scheduler runner with a 1-minute check interval
	a.schedulerRunner = scheduler.NewSchedulerRunner(a.schedulerService, 1*time.Minute)

	return a, nil
}

func NewMustApp(cfg config.Config) AppContainer {
	a, err := NewApp(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

func (a *app) scannerServiceWithDB(db *gorm.DB) scannerPort.Service {
	return scanner.NewScannerService(storage.NewScannerRepo(db))
}

func (a *app) ScannerService(ctx context.Context) scannerPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.scannerService == nil {
			a.scannerService = a.scannerServiceWithDB(a.db)
		}
		return a.scannerService
	}
	return a.scannerServiceWithDB(db)
}

func (a *app) schedulerServiceWithDB(db *gorm.DB) schedulerPort.Service {
	scannerService := scanner.NewScannerService(storage.NewScannerRepo(db))

	// Get the asset repo for the given DB context
	assetRepo := storage.NewAssetRepo(db)

	// Create scanners for this context
	nmapScanner := scanner.NewNmapRunner(assetRepo)
	vcenterScanner := scanner.NewVCenterRunner(assetRepo)
	domainScanner := scanner.NewDomainRunner(assetRepo)
	firewallScanner := scanner.NewFirewallRunner(assetRepo) 

	return scheduler.NewSchedulerService(
		storage.NewSchedulerRepo(db),
		scannerService,
		nmapScanner,
		vcenterScanner,
		domainScanner,
		firewallScanner, // Include firewall scanner
	)
}

func (a *app) SchedulerService(ctx context.Context) schedulerPort.Service {
	db := appCtx.GetDB(ctx)
	if db == nil {
		if a.schedulerService == nil {
			a.schedulerService = a.schedulerServiceWithDB(a.db)
		}
		return a.schedulerService
	}
	return a.schedulerServiceWithDB(db)
}

// StartScheduler begins the scheduler runner
func (a *app) StartScheduler() {
	if a.schedulerRunner != nil {
		a.schedulerRunner.Start()
	}
}

// StopScheduler halts the scheduler runner
func (a *app) StopScheduler() {
	if a.schedulerRunner != nil {
		a.schedulerRunner.Stop()
	}
}

// For access from service_getters.go
func (a *app) GetAPIScannerService() *service.ScannerService {
	return a.apiScannerService
}
