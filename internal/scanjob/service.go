package scanjob

import (
	"context"
	"errors"

	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
)

var (
	ErrJobNotComplete   = errors.New("scan job is not complete")
	ErrJobNotFound      = errors.New("scan job not found")
	ErrInvalidScanJobID = errors.New("invalid scan job ID")
	ErrScanJobNotFound  = errors.New("scan job not found")
)

// service implements scanJobPort.Service
type service struct {
	repo         scanJobPort.Repo
	assetService assetPort.Service
}

// NewScanJobService creates a new scan job service
func NewScanJobService(repo scanJobPort.Repo, assetService assetPort.Service) scanJobPort.Service {
	return &service{
		repo:         repo,
		assetService: assetService,
	}
}

// GetAssetService returns the asset service
func (s *service) GetAssetService() assetPort.Service {
	return s.assetService
}

// GetJobs retrieves scan jobs based on filter, pagination, and sorting
func (s *service) GetJobs(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error) {
	return s.repo.Get(ctx, filter, limit, offset, sortOptions...)
}

// GetJobByID retrieves a single scan job by its ID
func (s *service) GetJobByID(ctx context.Context, id int64) (*domain.ScanJob, error) {
	return s.repo.GetByID(ctx, id)
}

// DiffJobs compares two scan jobs and returns the assets that are in the newer job but not in the older job,
// and the assets that are in the older job but not in the newer job
func (s *service) DiffJobs(ctx context.Context, newerJobID, olderJobID int64, limit, offset int) ([]assetDomain.AssetDomain, []assetDomain.AssetDomain, int, int, error) {
	newerJobResult, olderJobResult, err := s.repo.GetJobsForComparison(ctx, newerJobID, olderJobID)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	if newerJobResult.JobStatus != "Completed" {
		return nil, nil, 0, 0, errors.New("newer job is not complete")
	}

	if olderJobResult.JobStatus != "Completed" {
		return nil, nil, 0, 0, errors.New("older job is not complete")
	}

	olderIDMap := make(map[string]struct{}, len(olderJobResult.AssetIDs))
	for _, id := range olderJobResult.AssetIDs {
		olderIDMap[id] = struct{}{}
	}

	newerIDMap := make(map[string]struct{}, len(newerJobResult.AssetIDs))
	for _, id := range newerJobResult.AssetIDs {
		newerIDMap[id] = struct{}{}
	}

	// Find new asset IDs (in newer job but not in older)
	var newAssetIDs []assetDomain.AssetUUID
	for _, id := range newerJobResult.AssetIDs {
		if _, exists := olderIDMap[id]; !exists {
			assetUUID, err := assetDomain.AssetUUIDFromString(id)
			if err != nil {
				continue // Skip invalid UUIDs
			}
			newAssetIDs = append(newAssetIDs, assetUUID)
		}
	}

	// Find missing asset IDs (in older job but not in newer)
	var missingAssetIDs []assetDomain.AssetUUID
	for _, id := range olderJobResult.AssetIDs {
		if _, exists := newerIDMap[id]; !exists {
			assetUUID, err := assetDomain.AssetUUIDFromString(id)
			if err != nil {
				continue // Skip invalid UUIDs
			}
			missingAssetIDs = append(missingAssetIDs, assetUUID)
		}
	}

	// Total counts before pagination
	newAssetsCount := len(newAssetIDs)
	missingAssetsCount := len(missingAssetIDs)

	// Skip pagination if both limit and offset are zero
	if limit == 0 && offset == 0 {
		// Get all new assets
		var newAssets []assetDomain.AssetDomain
		if len(newAssetIDs) > 0 {
			newAssets, err = s.assetService.GetByIDs(ctx, newAssetIDs)
			if err != nil {
				return nil, nil, 0, 0, err
			}
		}

		// Get all missing assets
		var missingAssets []assetDomain.AssetDomain
		if len(missingAssetIDs) > 0 {
			missingAssets, err = s.assetService.GetByIDs(ctx, missingAssetIDs)
			if err != nil {
				return nil, nil, 0, 0, err
			}
		}

		return newAssets, missingAssets, newAssetsCount, missingAssetsCount, nil
	}

	// Apply pagination if limit or offset is non-zero
	// Handle pagination for new assets
	var paginatedNewAssetIDs []assetDomain.AssetUUID
	if len(newAssetIDs) > 0 {
		startIdx := offset
		endIdx := offset + limit

		if startIdx < len(newAssetIDs) {
			if endIdx > len(newAssetIDs) {
				endIdx = len(newAssetIDs)
			}
			paginatedNewAssetIDs = newAssetIDs[startIdx:endIdx]
		}
	}

	// Handle pagination for missing assets
	var paginatedMissingAssetIDs []assetDomain.AssetUUID
	if len(missingAssetIDs) > 0 {
		startIdx := offset
		endIdx := offset + limit

		if startIdx < len(missingAssetIDs) {
			if endIdx > len(missingAssetIDs) {
				endIdx = len(missingAssetIDs)
			}
			paginatedMissingAssetIDs = missingAssetIDs[startIdx:endIdx]
		}
	}

	// Get new assets with pagination
	var newAssets []assetDomain.AssetDomain
	if len(paginatedNewAssetIDs) > 0 {
		newAssets, err = s.assetService.GetByIDs(ctx, paginatedNewAssetIDs)
		if err != nil {
			return nil, nil, 0, 0, err
		}
	}

	// Get missing assets with pagination
	var missingAssets []assetDomain.AssetDomain
	if len(paginatedMissingAssetIDs) > 0 {
		missingAssets, err = s.assetService.GetByIDs(ctx, paginatedMissingAssetIDs)
		if err != nil {
			return nil, nil, 0, 0, err
		}
	}

	return newAssets, missingAssets, newAssetsCount, missingAssetsCount, nil
}

func (s *service) ExportDiffJobs(ctx context.Context, newerJobID, olderJobID int64) (*assetDomain.ExportData, error) {
	newAssets, missingAssets, _, _, err := s.DiffJobs(ctx, newerJobID, olderJobID, 0, 0)
	if err != nil {
		switch err.Error() {
		case "newer job is not complete", "older job is not complete":
			return nil, ErrJobNotComplete
		case "scan job not found":
			return nil, ErrScanJobNotFound
		default:
			return nil, err
		}
	}

	exportData := &assetDomain.ExportData{
		Assets:    make([]map[string]interface{}, 0),
		Ports:     make([]map[string]interface{}, 0),
		VMwareVMs: make([]map[string]interface{}, 0),
		AssetIPs:  make([]map[string]interface{}, 0),
	}

	for _, asset := range newAssets {
		assetMap, err := assetDomain.ToMap(asset)
		if err != nil {
			return nil, err
		}
		assetMap["status"] = "new_asset"
		exportData.Assets = append(exportData.Assets, assetMap)

		for _, port := range asset.Ports {
			portMap, err := assetDomain.ToMap(port)
			if err != nil {
				return nil, err
			}
			exportData.Ports = append(exportData.Ports, portMap)
		}

		for _, vm := range asset.VMwareVMs {
			vmMap, err := assetDomain.ToMap(vm)
			if err != nil {
				return nil, err
			}
			exportData.VMwareVMs = append(exportData.VMwareVMs, vmMap)
		}

		for _, ip := range asset.AssetIPs {
			ipMap, err := assetDomain.ToMap(ip)
			if err != nil {
				return nil, err
			}
			exportData.AssetIPs = append(exportData.AssetIPs, ipMap)
		}
	}

	for _, asset := range missingAssets {
		assetMap, err := assetDomain.ToMap(asset)
		if err != nil {
			return nil, err
		}
		assetMap["status"] = "missing_asset"
		exportData.Assets = append(exportData.Assets, assetMap)

		for _, port := range asset.Ports {
			portMap, err := assetDomain.ToMap(port)
			if err != nil {
				return nil, err
			}
			exportData.Ports = append(exportData.Ports, portMap)
		}

		for _, vm := range asset.VMwareVMs {
			vmMap, err := assetDomain.ToMap(vm)
			if err != nil {
				return nil, err
			}
			exportData.VMwareVMs = append(exportData.VMwareVMs, vmMap)
		}

		for _, ip := range asset.AssetIPs {
			ipMap, err := assetDomain.ToMap(ip)
			if err != nil {
				return nil, err
			}
			exportData.AssetIPs = append(exportData.AssetIPs, ipMap)
		}
	}

	return exportData, nil
}
