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
	asset, err := s.repo.GetByID(ctx, assetUUID)
	if err != nil {
		return nil, err
	}

	if asset == nil {
		return nil, ErrAssetNotFound
	}

	return asset, nil
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
	affected_rows, err := s.repo.Delete(ctx, assetUUID)

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

	return s.repo.DeleteMultiple(ctx, assetUUIDs)
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

	// Write Assets section header
	if err := writer.Write([]string{"ASSET COLUMNS NAME"}); err != nil {
		return nil, ErrExportFailed
	}

	// Write asset column headers if there is data
	if len(exportData.Assets) > 0 {
		headers := make([]string, 0, len(exportData.Assets[0]))
		for key := range exportData.Assets[0] {
			headers = append(headers, key)
		}

		if err := writer.Write(headers); err != nil {
			return nil, ErrExportFailed
		}

		// Write asset data rows
		for _, asset := range exportData.Assets {
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

	// Write an empty line between sections
	if err := writer.Write([]string{}); err != nil {
		return nil, ErrExportFailed
	}

	// Write Ports section header
	if err := writer.Write([]string{"PORT COLUMNS NAME"}); err != nil {
		return nil, ErrExportFailed
	}

	// Write port column headers if there is data
	if len(exportData.Ports) > 0 {
		headers := make([]string, 0, len(exportData.Ports[0]))
		for key := range exportData.Ports[0] {
			headers = append(headers, key)
		}

		if err := writer.Write(headers); err != nil {
			return nil, ErrExportFailed
		}

		// Write port data rows
		for _, port := range exportData.Ports {
			row := make([]string, len(headers))
			for i, header := range headers {
				if val, ok := port[header]; ok {
					row[i] = toString(val)
				}
			}

			if err := writer.Write(row); err != nil {
				return nil, ErrExportFailed
			}
		}
	}

	// Write an empty line between sections
	if err := writer.Write([]string{}); err != nil {
		return nil, ErrExportFailed
	}

	// Write VMwareVMs section header
	if err := writer.Write([]string{"VMwareVMs COLUMNS NAME"}); err != nil {
		return nil, ErrExportFailed
	}

	// Write VMware VM column headers if there is data
	if len(exportData.VMwareVMs) > 0 {
		headers := make([]string, 0, len(exportData.VMwareVMs[0]))
		for key := range exportData.VMwareVMs[0] {
			headers = append(headers, key)
		}

		if err := writer.Write(headers); err != nil {
			return nil, ErrExportFailed
		}

		// Write VMware VM data rows
		for _, vm := range exportData.VMwareVMs {
			row := make([]string, len(headers))
			for i, header := range headers {
				if val, ok := vm[header]; ok {
					row[i] = toString(val)
				}
			}

			if err := writer.Write(row); err != nil {
				return nil, ErrExportFailed
			}
		}
	}

	// Write an empty line between sections
	if err := writer.Write([]string{}); err != nil {
		return nil, ErrExportFailed
	}

	// Write AssetIPs section header
	if err := writer.Write([]string{"AssetIPs COLUMNS NAME"}); err != nil {
		return nil, ErrExportFailed
	}

	// Write asset IPs column headers if there is data
	if len(exportData.AssetIPs) > 0 {
		headers := make([]string, 0, len(exportData.AssetIPs[0]))
		for key := range exportData.AssetIPs[0] {
			headers = append(headers, key)
		}

		if err := writer.Write(headers); err != nil {
			return nil, ErrExportFailed
		}

		// Write asset IPs data rows
		for _, assetIP := range exportData.AssetIPs {
			row := make([]string, len(headers))
			for i, header := range headers {
				if val, ok := assetIP[header]; ok {
					row[i] = toString(val)
				}
			}

			if err := writer.Write(row); err != nil {
				return nil, ErrExportFailed
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
