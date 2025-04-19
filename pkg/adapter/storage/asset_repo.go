package storage

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

// NewAssetRepo creates a new asset repository
func NewAssetRepo(db *gorm.DB) assetPort.Repo {
	return &assetRepository{
		db: db,
	}
}

// assetRepository implements the assetPort.Repo interface
type assetRepository struct {
	db *gorm.DB
}

// Create implements the asset repository Create method with duplicate handling
func (r *assetRepository) Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	log.Printf("Creating asset with %d IPs", len(asset.IPs))

	// If no IPs provided, cannot proceed
	if len(asset.IPs) == 0 {
		return domain.AssetUUID{}, errors.New("at least one IP address must be provided")
	}

	// Get the primary IP (first in the list)
	primaryIP := asset.IPs[0]

	// Check if an asset with this IP already exists
	var existingAssetIP types.AssetIP
	result := r.db.WithContext(ctx).Table("asset_ips").Where("ip_address = ?", primaryIP).First(&existingAssetIP)

	if result.Error == nil {
		// Asset IP exists, get the associated asset
		var existingAsset types.Asset
		if err := r.db.WithContext(ctx).Table("assets").Where("id = ?", existingAssetIP.AssetID).First(&existingAsset).Error; err != nil {
			log.Printf("Error finding existing asset for IP %s: %v", primaryIP, err)
			return domain.AssetUUID{}, err
		}

		log.Printf("Asset with IP %s already exists (Asset ID: %s)", primaryIP, existingAsset.ID)

		now := time.Now()

		// Prepare update data for asset
		updates := map[string]interface{}{
			"updated_at": now,
		}

		// Only update non-empty fields
		if asset.Name != "" {
			updates["name"] = asset.Name
		}
		if asset.Domain != "" {
			updates["domain"] = asset.Domain
		}
		if asset.Hostname != "" {
			updates["hostname"] = asset.Hostname
		}
		if asset.OSName != "" {
			updates["os_name"] = asset.OSName
		}
		if asset.OSVersion != "" {
			updates["os_version"] = asset.OSVersion
		}
		if asset.Type != "" {
			updates["asset_type"] = asset.Type
		}
		if asset.Description != "" {
			updates["description"] = asset.Description
		}

		// Begin transaction
		tx := r.db.WithContext(ctx).Begin()
		if tx.Error != nil {
			return domain.AssetUUID{}, tx.Error
		}

		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			}
		}()

		// Update the asset
		if err := tx.Table("assets").Where("id = ?", existingAsset.ID).Updates(updates).Error; err != nil {
			tx.Rollback()
			log.Printf("Error updating existing asset: %v", err)
			return domain.AssetUUID{}, err
		}

		// Process additional IPs if any
		for _, ip := range asset.IPs {
			// Skip if it's the primary IP which we know already exists
			if ip == primaryIP {
				continue
			}

			// Check if this IP already exists
			var count int64
			if err := tx.Table("asset_ips").Where("ip_address = ?", ip).Count(&count).Error; err != nil {
				tx.Rollback()
				return domain.AssetUUID{}, err
			}

			// If IP doesn't exist, add it
			if count == 0 {
				newAssetIP := types.AssetIP{
					ID:        uuid.New().String(),
					AssetID:   existingAsset.ID,
					IPAddress: ip,
					CreatedAt: now,
					UpdatedAt: &now,
				}

				if err := tx.Table("asset_ips").Create(&newAssetIP).Error; err != nil {
					tx.Rollback()
					log.Printf("Error adding new IP %s to asset: %v", ip, err)
					return domain.AssetUUID{}, err
				}
			}
		}

		// Commit the transaction
		if err := tx.Commit().Error; err != nil {
			log.Printf("Error committing transaction: %v", err)
			return domain.AssetUUID{}, err
		}

		// Return the existing asset ID as UUID
		existingID, err := domain.AssetUUIDFromString(existingAsset.ID)
		if err != nil {
			log.Printf("Error parsing existing asset UUID: %v", err)
			return domain.AssetUUID{}, err
		}

		return existingID, nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// If error is not "record not found", something else went wrong
		log.Printf("Error checking for existing asset IP: %v", result.Error)
		return domain.AssetUUID{}, result.Error
	}

	// No existing asset found with this IP, create a new one
	assetRecord, assetIPs := mapper.AssetDomain2Storage(asset)

	// Begin transaction
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return domain.AssetUUID{}, tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create the asset
	if err := tx.Table("assets").Create(assetRecord).Error; err != nil {
		tx.Rollback()
		log.Printf("Error creating asset: %v", err)
		return domain.AssetUUID{}, err
	}

	// Create all asset IPs
	for _, assetIP := range assetIPs {
		if err := tx.Table("asset_ips").Create(assetIP).Error; err != nil {
			tx.Rollback()
			log.Printf("Error creating asset IP %s: %v", assetIP.IPAddress, err)
			return domain.AssetUUID{}, err
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		log.Printf("Error committing transaction: %v", err)
		return domain.AssetUUID{}, err
	}

	log.Printf("Successfully created new asset with ID: %s and %d IPs", asset.ID, len(asset.IPs))
	return asset.ID, nil
}

// getAssetIPs retrieves all IPs associated with an asset
func (r *assetRepository) getAssetIPs(ctx context.Context, assetID string) ([]types.AssetIP, error) {
	var assetIPs []types.AssetIP
	err := r.db.WithContext(ctx).Table("asset_ips").
		Where("asset_id = ?", assetID).
		Where("deleted_at IS NULL").
		Find(&assetIPs).Error

	return assetIPs, err
}

// GetByID retrieves an asset by its ID
func (r *assetRepository) GetByID(ctx context.Context, assetID domain.AssetUUID) (*domain.AssetDomain, error) {
	var asset types.Asset
	err := r.db.WithContext(ctx).Table("assets").
		Where("id = ?", assetID.String()).
		Where("deleted_at IS NULL").
		First(&asset).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	// Get asset IPs
	assetIPs, err := r.getAssetIPs(ctx, assetID.String())
	if err != nil {
		return nil, err
	}

	// Convert to domain model
	assetDomain, err := mapper.AssetStorage2Domain(asset, assetIPs)
	if err != nil {
		return nil, err
	}

	return assetDomain, nil
}

// Get retrieves assets based on filters
func (r *assetRepository) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	query := r.db.WithContext(ctx).Table("assets").Where("deleted_at IS NULL")

	// Apply filters
	if assetFilter.Name != "" {
		query = query.Where("name LIKE ?", "%"+assetFilter.Name+"%")
	}
	if assetFilter.Domain != "" {
		query = query.Where("domain LIKE ?", "%"+assetFilter.Domain+"%")
	}
	if assetFilter.Hostname != "" {
		query = query.Where("hostname LIKE ?", "%"+assetFilter.Hostname+"%")
	}
	if assetFilter.OSName != "" {
		query = query.Where("os_name LIKE ?", "%"+assetFilter.OSName+"%")
	}
	if assetFilter.OSVersion != "" {
		query = query.Where("os_version LIKE ?", "%"+assetFilter.OSVersion+"%")
	}
	if assetFilter.Type != "" {
		query = query.Where("asset_type = ?", assetFilter.Type)
	}

	// Handle IP filter specially - need to join with asset_ips table
	if assetFilter.IP != "" {
		// Join with asset_ips and filter by IP
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id").
			Where("asset_ips.ip_address LIKE ?", "%"+assetFilter.IP+"%").
			Where("asset_ips.deleted_at IS NULL")
	}

	var assets []types.Asset
	if err := query.Find(&assets).Error; err != nil {
		return nil, err
	}

	// Convert to domain models
	var results []domain.AssetDomain
	for _, asset := range assets {
		// Get IPs for this asset
		assetIPs, err := r.getAssetIPs(ctx, asset.ID)
		if err != nil {
			continue
		}

		// Convert to domain model
		assetDomain, err := mapper.AssetStorage2Domain(asset, assetIPs)
		if err != nil {
			continue
		}

		results = append(results, *assetDomain)
	}

	return results, nil
}

// LinkAssetToScanJob links an asset to a scan job record
func (r *assetRepository) LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error {
	log.Printf("Linking asset %s to scan job %d", assetID.String(), scanJobID)

	// Create an AssetScanJob record
	assetScanJob := types.AssetScanJob{
		AssetID:   assetID.String(),
		ScanJobID: scanJobID,
	}

	// Insert the record
	err := r.db.WithContext(ctx).Table("asset_scan_jobs").Create(&assetScanJob).Error
	if err != nil {
		// Check if it's a duplicate entry error (asset already linked to this scan job)
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "Duplicate entry") {
			log.Printf("Asset %s already linked to scan job %d", assetID.String(), scanJobID)
			return nil
		}
		log.Printf("Error linking asset to scan job: %v", err)
		return err
	}

	log.Printf("Successfully linked asset %s to scan job %d", assetID.String(), scanJobID)
	return nil
}

// UpdateAssetPorts updates port information for an asset based on scan results
func (r *assetRepository) UpdateAssetPorts(ctx context.Context, assetID domain.AssetUUID, ports []types.Port) error {
	log.Printf("Updating ports for asset %s, count: %d", assetID.String(), len(ports))

	// Begin a transaction
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Delete existing ports for this asset
	if err := tx.Where("asset_id = ?", assetID.String()).Delete(&types.Port{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Insert new ports
	for _, port := range ports {
		port.AssetID = assetID.String()
		if err := tx.Create(&port).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	// Commit the transaction
	return tx.Commit().Error
}
