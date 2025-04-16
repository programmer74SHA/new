package asset

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
)

type service struct {
	assetService assetPort.Service
	repo         assetPort.Repo
}

func NewAssetService(assetService assetPort.Service, repo assetPort.Repo) assetPort.Service {
	return &service{
		assetService: assetService,
		repo:         repo,
	}
}

func (s *service) CreateAsset(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	panic("Not Implemented")
}
func (s *service) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	panic("Not Implemented")
}
func (s *service) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	panic("Not Implemented")
}
