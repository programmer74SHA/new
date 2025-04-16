package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

type Repo interface {
	Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error)
	GetByID(ctx context.Context, UUID domain.AssetUUID) (*domain.AssetDomain, error)
	Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error)
	LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error
}
