package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
)

type Service interface {
	GetJobs(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error)
	GetJobByID(ctx context.Context, id domain.ScanJobUUID) (*domain.ScanJob, error)
}
