package app

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"

	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
	AssetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	ScannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	SchedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	UserPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/user/port"
	"gorm.io/gorm"
)

type AppContainer interface {
	AssetService(ctx context.Context) AssetPort.Service
	UserService(ctx context.Context) UserPort.Service
	ScannerService(ctx context.Context) ScannerPort.Service
	SchedulerService(ctx context.Context) SchedulerPort.Service
	StartScheduler()
	StopScheduler()
	ScanJobService(ctx context.Context) scanJobPort.Service
	Config() config.Config
	DB() *gorm.DB

	// New method to access the API scanner service
	GetAPIScannerService() *service.ScannerService
}
