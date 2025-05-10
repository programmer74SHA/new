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
	ErrAssetNotFound     = errors.New("asset not found")
	ErrInvalidAssetUUID  = errors.New("invalid asset UUID")
	ErrAssetCreateFailed = errors.New("failed to create asset")
	ErrAssetUpdateFailed = errors.New("failed to update asset")
	ErrAssetDeleteFailed = errors.New("failed to delete asset")
	ErrExportFailed      = errors.New("failed to export assets")
	ErrOSNamesFailed     = errors.New("failed to get OS names")
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
		return ErrAssetUpdateFailed
	}

	return nil
}

func (s *service) DeleteAsset(ctx context.Context, assetUUID domain.AssetUUID) error {
	affected_rows, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUID(assetUUID))

	if err != nil {
		return ErrAssetDeleteFailed
	}

	if affected_rows == 0 {
		return ErrAssetNotFound
	}

	return nil
}

func (s *service) DeleteAssets(ctx context.Context, assetUUIDs []domain.AssetUUID) error {
	if len(assetUUIDs) == 0 {
		return nil
	}

	_, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithUUIDs(assetUUIDs))
	return err
}

// DeleteAllAssets deletes all assets in the system
func (s *service) DeleteAllAssets(ctx context.Context) error {
	_, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsForAll())
	return err
}

// DeleteAllAssetsWithFilters deletes all assets matching the provided filters
func (s *service) DeleteAllAssetsWithFilters(ctx context.Context, filter domain.AssetFilters) error {
	_, err := s.repo.DeleteAssets(ctx, domain.NewDeleteParamsWithFilters(filter))
	return err
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

	var headers []string

	// Collect headers from all assets
	assetHeaders := make([]string, 0)
	if len(exportData.Assets) > 0 {
		for key := range exportData.Assets[0] {
			assetHeaders = append(assetHeaders, key)
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

	// Build a map of assets for lookup
	assetMap := make(map[string]map[string]interface{})
	for _, asset := range exportData.Assets {
		assetID := fmt.Sprint(asset["id"])
		assetMap[assetID] = asset
	}

	// Group VMwareVMs by asset ID for lookup
	vmMap := make(map[string][]map[string]interface{})
	for _, vm := range exportData.VMwareVMs {
		assetID := fmt.Sprint(vm["asset_id"])
		vmMap[assetID] = append(vmMap[assetID], vm)
	}

	// Create rows combining asset data with AssetIPs data
	// If an asset has multiple IPs, create multiple rows
	written := false

	// When there are AssetIPs, create rows based on them
	if len(exportData.AssetIPs) > 0 {
		for _, ip := range exportData.AssetIPs {
			assetID := fmt.Sprint(ip["asset_id"])

			asset, assetExists := assetMap[assetID]
			if !assetExists {
				continue
			}

			vms := vmMap[assetID]

			// If there are VMs, create a row for each VM
			if len(vms) > 0 {
				for _, vm := range vms {
					row := make([]string, len(headers))
					for i, header := range headers {
						if val, ok := asset[header]; ok {
							row[i] = toString(val)
						} else if val, ok := ip[header]; ok {
							row[i] = toString(val)
						} else if val, ok := vm[header]; ok {
							row[i] = toString(val)
						}
					}

					if err := writer.Write(row); err != nil {
						return nil, ErrExportFailed
					}
					written = true
				}
			} else {
				row := make([]string, len(headers))

				for i, header := range headers {
					if val, ok := asset[header]; ok {
						row[i] = toString(val)
					} else if val, ok := ip[header]; ok {
						row[i] = toString(val)
					}
				}

				if err := writer.Write(row); err != nil {
					return nil, ErrExportFailed
				}
				written = true
			}
		}
	}

	// If no AssetIPs data or no rows written yet, create rows based on assets
	if !written {
		for assetID, asset := range assetMap {
			vms := vmMap[assetID]

			if len(vms) > 0 {
				for _, vm := range vms {
					row := make([]string, len(headers))

					for i, header := range headers {
						if val, ok := asset[header]; ok {
							row[i] = toString(val)
						} else if val, ok := vm[header]; ok {
							row[i] = toString(val)
						}
					}

					if err := writer.Write(row); err != nil {
						return nil, ErrExportFailed
					}
				}
			} else {
				row := make([]string, len(headers))

				for i, header := range headers {
					if val, ok := asset[header]; ok {
						row[i] = toString(val)
					}
				}

				if err := writer.Write(row); err != nil {
					return nil, ErrExportFailed
				}
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, ErrExportFailed
	}

	return []byte(sb.String()), nil
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
