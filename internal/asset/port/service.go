package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

type Service interface {
	CreateAsset(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error)
	GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error)
	Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error)
}
