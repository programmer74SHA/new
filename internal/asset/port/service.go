package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

type Service interface {
	CreateAsset(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error)
	GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error)
	Get(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error)
	UpdateAsset(ctx context.Context, asset domain.AssetDomain) error
	DeleteAsset(ctx context.Context, assetUUID domain.AssetUUID) error
	DeleteAssets(ctx context.Context, assetUUIDs []domain.AssetUUID) error
	GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error)
	ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error)
	GenerateCSV(ctx context.Context, exportData *domain.ExportData) ([]byte, error)
}
