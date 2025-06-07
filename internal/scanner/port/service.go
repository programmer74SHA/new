package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

type Service interface {
	CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (int64, error)
	GetScannerByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error)
	UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error
	DeleteScanner(ctx context.Context, scannerID int64) error
	DeleteScanners(ctx context.Context, ids []string, filter *domain.ScannerFilter, exclude bool) (int, error)
	ListScanners(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error)
	UpdateScannerStatus(ctx context.Context, filter domain.ScannerFilter, ids []int64, status bool, exclude bool, updateAll bool) (int, error)
}
