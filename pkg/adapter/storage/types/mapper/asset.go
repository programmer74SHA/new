package mapper

import (
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func AssetDomain2Storage(asset domain.AssetDomain) *types.Asset {
	return &types.Asset{
		ID:          asset.ID.String(),
		Name:        &asset.Name,
		Domain:      &asset.Domain,
		Hostname:    asset.Hostname,
		OSName:      &asset.OSName,
		OSVersion:   &asset.OSVersion,
		Type:        asset.Type,
		IPAddress:   asset.IP,
		Description: &asset.Description,
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   &asset.UpdatedAt,
	}
}

func AssetStorage2Domain(asset types.Asset) (*domain.AssetDomain, error) {
	uid, err := domain.AssetUUIDFromString(asset.ID)

	return &domain.AssetDomain{
		ID:          uid,
		Name:        *asset.Name,
		Domain:      *asset.Domain,
		Hostname:    asset.Hostname,
		OSName:      *asset.OSName,
		OSVersion:   *asset.OSVersion,
		Type:        asset.Type,
		IP:          asset.IPAddress,
		Description: asset.Type,
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   *asset.UpdatedAt,
	}, err
}
