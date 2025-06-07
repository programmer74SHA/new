package asset

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
)

var (
	ErrAssetNotFound         = errors.New("asset not found")
	ErrInvalidAssetUUID      = errors.New("invalid asset UUID")
	ErrAssetCreateFailed     = errors.New("failed to create asset")
	ErrAssetUpdateFailed     = errors.New("failed to update asset")
	ErrAssetDeleteFailed     = errors.New("failed to delete asset")
	ErrExportFailed          = errors.New("failed to export assets")
	ErrOSNamesFailed         = errors.New("failed to get OS names")
	ErrIPAlreadyExists       = domain.ErrIPAlreadyExists
	ErrHostnameAlreadyExists = domain.ErrHostnameAlreadyExists
)

type service struct {
	repo assetPort.Repo
}

func NewAssetService(repo assetPort.Repo) assetPort.Service {
	return &service{
		repo: repo,
	}
}

func (s *service) CreateAsset(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	assetID, err := s.repo.Create(ctx, asset)
	if err != nil {
		if errors.Is(err, domain.ErrIPAlreadyExists) {
			return uuid.Nil, err
		}
		return uuid.Nil, ErrAssetCreateFailed
	}
	return assetID, nil
}

func (s *service) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	var assetUUIDs []domain.AssetUUID
	assetUUIDs = append(assetUUIDs, assetUUID)

	assets, err := s.repo.GetByIDs(ctx, assetUUIDs)
	if err != nil {
		return nil, err
	}

	if assets == nil {
		return nil, ErrAssetNotFound
	}

	if len(assets) == 0 {
		return nil, ErrAssetNotFound
	}

	return &assets[0], nil
}

func (s *service) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	assets, err := s.repo.GetByIDs(ctx, assetUUIDs)
	if err != nil {
		return nil, err
	}
	return assets, nil
}

func (s *service) Get(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	assets, total, err := s.repo.GetByFilter(ctx, assetFilter, limit, offset, sortOptions...)
	if err != nil {
		return nil, 0, err
	}

	return assets, total, nil
}

func (s *service) UpdateAsset(ctx context.Context, asset domain.AssetDomain) error {
	err := s.repo.Update(ctx, asset)
	if err != nil {
		if errors.Is(err, domain.ErrIPAlreadyExists) {
			return err
		}
		return ErrAssetUpdateFailed
	}

	return nil
}

// DeleteAssets handles all asset deletion scenarios based on the provided parameters
func (s *service) DeleteAssets(ctx context.Context, ids []string, filter *domain.AssetFilters, exclude bool) error {
	// Single Id case:
	if len(ids) == 1 && ids[0] != "All" {
		assetUUID, err := uuid.Parse(ids[0])
		if err != nil {
			return ErrInvalidAssetUUID
		}

		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUID(assetUUID))
		return checkDeletedAssetsErrors(affected_rows, err)
	} else if len(ids) == 1 && ids[0] == "All" {
		// Special case: "All" in IDs list
		// If "All" is specified with filters, use the filters to delete specific assets
		if filter != nil {
			affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithFilters(*filter))
			return checkDeletedAssetsErrors(affected_rows, err)
		}

		// Delete all assets without filters
		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsForAll())
		return checkDeletedAssetsErrors(affected_rows, err)
	}

	// Convert string IDs to UUIDs
	assetUUIDs := make([]domain.AssetUUID, 0, len(ids))
	for _, id := range ids {
		assetUUID, err := uuid.Parse(id)
		if err != nil {
			return ErrInvalidAssetUUID
		}
		assetUUIDs = append(assetUUIDs, assetUUID)
	}

	// Case with both filters and IDs
	if filter != nil {
		if exclude {
			// Delete assets matching filter except those with the specified IDs
			affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithFiltersExclude(*filter, assetUUIDs))
			return checkDeletedAssetsErrors(affected_rows, err)
		}

		// Delete assets that match both specific IDs and filter criteria
		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDsAndFilters(assetUUIDs, *filter))
		return checkDeletedAssetsErrors(affected_rows, err)
	}

	// Simple case: either include or exclude specific IDs
	if exclude {
		if len(assetUUIDs) == 0 {
			affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsForAll())
			return checkDeletedAssetsErrors(affected_rows, err)
		}

		affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDsExclude(assetUUIDs))
		return checkDeletedAssetsErrors(affected_rows, err)
	}

	if len(assetUUIDs) == 0 {
		return nil
	}

	affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDs(assetUUIDs))
	return checkDeletedAssetsErrors(affected_rows, err)
}

// ExportAssets exports assets based on asset IDs and export type
func (s *service) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	exportData, err := s.repo.ExportAssets(ctx, assetIDs, exportType, selectedColumns)
	if err != nil {
		return nil, ErrExportFailed
	}
	return exportData, nil
}

// GenerateCSV generates a CSV file from export data
func (s *service) GenerateCSV(ctx context.Context, exportData *domain.ExportData) ([]byte, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	// Validate the export data
	if exportData == nil {
		return nil, fmt.Errorf("export data is nil")
	}

	// used for diff exports
	hasStatusField := false
	if len(exportData.Assets) > 0 {
		_, hasStatusField = exportData.Assets[0]["status"]
	}

	var headers []string
	if hasStatusField {
		headers = append(headers, "status")
	}

	// Collect headers from all assets
	assetHeaders := make([]string, 0)
	if len(exportData.Assets) > 0 {
		for key := range exportData.Assets[0] {
			if key != "status" || !hasStatusField {
				assetHeaders = append(assetHeaders, key)
			}
		}
	}

	// Collect headers from AssetIPs
	ipHeaders := make([]string, 0)
	if len(exportData.AssetIPs) > 0 {
		for key := range exportData.AssetIPs[0] {
			if key != "asset_id" {
				ipHeaders = append(ipHeaders, key)
			}
		}
	}

	// Collect headers from VMwareVMs
	vmHeaders := make([]string, 0)
	if len(exportData.VMwareVMs) > 0 {
		for key := range exportData.VMwareVMs[0] {
			if key != "asset_id" {
				vmHeaders = append(vmHeaders, key)
			}
		}
	}

	headers = append(headers, assetHeaders...)
	headers = append(headers, ipHeaders...)
	headers = append(headers, vmHeaders...)

	// Write headers
	if err := writer.Write(headers); err != nil {
		return nil, ErrExportFailed
	}

	// Create a map to store assets by their ID
	assetByID := make(map[string]map[string]interface{})

	// Group IPs by asset ID for lookup
	ipsByAssetID := make(map[string][]map[string]interface{})
	for _, ip := range exportData.AssetIPs {
		assetID := fmt.Sprint(ip["asset_id"])
		ipsByAssetID[assetID] = append(ipsByAssetID[assetID], ip)
	}

	// Group VMwareVMs by asset ID for lookup
	vmsByAssetID := make(map[string][]map[string]interface{})
	for _, vm := range exportData.VMwareVMs {
		assetID := fmt.Sprint(vm["asset_id"])
		vmsByAssetID[assetID] = append(vmsByAssetID[assetID], vm)
	}

	// Get all unique asset IDs from all data sources
	allAssetIDs := make(map[string]bool)

	for _, ip := range exportData.AssetIPs {
		assetID := fmt.Sprint(ip["asset_id"])
		allAssetIDs[assetID] = true
	}

	for _, vm := range exportData.VMwareVMs {
		assetID := fmt.Sprint(vm["asset_id"])
		allAssetIDs[assetID] = true
	}

	// Create a map of assets by their ID from the asset list
	for _, asset := range exportData.Assets {
		if id, ok := asset["id"]; ok {
			assetID := fmt.Sprint(id)
			assetByID[assetID] = asset
			allAssetIDs[assetID] = true
		}
	}

	// Process each asset ID to create CSV rows
	for assetID := range allAssetIDs {
		ips := ipsByAssetID[assetID]
		vms := vmsByAssetID[assetID]
		asset := assetByID[assetID]

		if asset == nil {
			asset = make(map[string]interface{})
			asset["id"] = assetID
		}

		// If there are both IPs and VMs for this asset
		if len(ips) > 0 && len(vms) > 0 {
			// For each IP and VM combination, create a row
			for _, ip := range ips {
				for _, vm := range vms {
					row := make([]string, len(headers))

					row = fillRowFromAsset(row, headers, asset)

					row = fillRowFromSource(row, headers, ip)
					row = fillRowFromSource(row, headers, vm)

					if err := writer.Write(row); err != nil {
						return nil, ErrExportFailed
					}
				}
			}
		} else if len(ips) > 0 {
			// Only IPs, no VMs
			for _, ip := range ips {
				row := make([]string, len(headers))

				row = fillRowFromAsset(row, headers, asset)

				row = fillRowFromSource(row, headers, ip)

				if err := writer.Write(row); err != nil {
					return nil, ErrExportFailed
				}
			}
		} else if len(vms) > 0 {
			// Only VMs, no IPs
			for _, vm := range vms {
				row := make([]string, len(headers))

				row = fillRowFromAsset(row, headers, asset)

				row = fillRowFromSource(row, headers, vm)

				if err := writer.Write(row); err != nil {
					return nil, ErrExportFailed
				}
			}
		} else {
			// No IPs or VMs, just the asset
			row := make([]string, len(headers))
			row = fillRowFromAsset(row, headers, asset)

			if err := writer.Write(row); err != nil {
				return nil, ErrExportFailed
			}
		}
	}

	for _, asset := range exportData.Assets {
		var assetID string
		if id, ok := asset["id"]; ok {
			assetID = fmt.Sprint(id)
			if allAssetIDs[assetID] {
				continue
			}
		}

		row := make([]string, len(headers))
		row = fillRowFromAsset(row, headers, asset)

		if err := writer.Write(row); err != nil {
			return nil, ErrExportFailed
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, ErrExportFailed
	}

	return []byte(sb.String()), nil
}

// fillRowFromAsset fills a row with data from an asset map
func fillRowFromAsset(row []string, headers []string, asset map[string]interface{}) []string {
	for i, header := range headers {
		if val, ok := asset[header]; ok {
			row[i] = toString(val)
		}
	}
	return row
}

// fillRowFromSource fills a row with data from a source map
func fillRowFromSource(row []string, headers []string, source map[string]interface{}) []string {
	for i, header := range headers {
		if val, ok := source[header]; ok {
			row[i] = toString(val)
		}
	}
	return row
}

// toString converts an interface to a string
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(strings.Replace(fmt.Sprint(v), "\n", " ", -1))
}

// GetDistinctOSNames returns a list of distinct OS names from all assets
func (s *service) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	osNames, err := s.repo.GetDistinctOSNames(ctx)
	if err != nil {
		return nil, ErrOSNamesFailed
	}
	return osNames, nil
}

func checkDeletedAssetsErrors(affected_rows int, err error) error {
	if err != nil {
		return ErrAssetDeleteFailed
	}

	if affected_rows == 0 {
		return ErrAssetNotFound
	}

	return nil
}
