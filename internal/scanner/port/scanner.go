package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

type Repo interface {
	Create(ctx context.Context, scanner domain.ScannerDomain) (int64, error)
	GetByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error)
	Update(ctx context.Context, scanner domain.ScannerDomain) error
	Delete(ctx context.Context, scannerID int64) error
	DeleteBatch(ctx context.Context, params domain.DeleteParams) (int, error)
	List(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error)
	UpdateScannerStatus(ctx context.Context, params domain.StatusUpdateParams) (int, error)
}
