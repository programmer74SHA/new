package port

import (
	"context"

	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
)

type Service interface {
	GetJobs(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error)
	GetJobByID(ctx context.Context, id int64) (*domain.ScanJob, error)
	DiffJobs(ctx context.Context, newerJobID, olderJobID int64, limit, offset int) ([]assetDomain.AssetDomain, []assetDomain.AssetDomain, int, int, error)
	ExportDiffJobs(ctx context.Context, newerJobID, olderJobID int64) (*assetDomain.ExportData, error)
	GetAssetService() assetPort.Service
}
