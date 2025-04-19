package mapper

import (
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func AssetDomain2Storage(asset domain.AssetDomain) (*types.Asset, []*types.AssetIP) {
	assetStorage := &types.Asset{
		ID:          asset.ID.String(),
		Name:        &asset.Name,
		Domain:      &asset.Domain,
		Hostname:    asset.Hostname,
		OSName:      &asset.OSName,
		OSVersion:   &asset.OSVersion,
		Type:        asset.Type,
		Description: &asset.Description,
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   &asset.UpdatedAt,
	}

	// Create AssetIP objects for each IP
	assetIPs := make([]*types.AssetIP, 0, len(asset.IPs))
	for _, ip := range asset.IPs {
		assetIPs = append(assetIPs, &types.AssetIP{
			ID:        uuid.New().String(),
			AssetID:   asset.ID.String(),
			IPAddress: ip,
			CreatedAt: asset.CreatedAt,
			UpdatedAt: &asset.UpdatedAt,
		})
	}

	return assetStorage, assetIPs
}

func AssetStorage2Domain(asset types.Asset, assetIPs []types.AssetIP) (*domain.AssetDomain, error) {
	uid, err := domain.AssetUUIDFromString(asset.ID)
	if err != nil {
		return nil, err
	}

	// Extract IPs from assetIPs
	ips := make([]string, 0, len(assetIPs))
	for _, ip := range assetIPs {
		ips = append(ips, ip.IPAddress)
	}

	var name, domainStr, osName, osVersion, description string
	if asset.Name != nil {
		name = *asset.Name
	}
	if asset.Domain != nil {
		domainStr = *asset.Domain
	}
	if asset.OSName != nil {
		osName = *asset.OSName
	}
	if asset.OSVersion != nil {
		osVersion = *asset.OSVersion
	}
	if asset.Description != nil {
		description = *asset.Description
	}

	var updatedAt time.Time
	if asset.UpdatedAt != nil {
		updatedAt = *asset.UpdatedAt
	}

	return &domain.AssetDomain{
		ID:          uid,
		Name:        name,
		Domain:      domainStr,
		Hostname:    asset.Hostname,
		OSName:      osName,
		OSVersion:   osVersion,
		Type:        asset.Type,
		IPs:         ips,
		Description: description,
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   updatedAt,
	}, nil
}
