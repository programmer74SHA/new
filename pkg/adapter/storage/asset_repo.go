package storage

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
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
	log.Printf("Creating asset: %s", asset.IP)

	// Check if an asset with this IP already exists
	var existingAsset types.Asset
	result := r.db.WithContext(ctx).Table("assets").Where("ip_address = ?", asset.IP).First(&existingAsset)

	if result.Error == nil {
		// Asset exists, update it instead of creating new one
		log.Printf("Asset with IP %s already exists (ID: %s)", asset.IP, existingAsset.ID)

		now := time.Now()

		// Prepare update data
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

		// Perform the update
		updateErr := r.db.WithContext(ctx).Table("assets").Where("id = ?", existingAsset.ID).Updates(updates).Error
		if updateErr != nil {
			log.Printf("Error updating existing asset: %v", updateErr)
			return domain.AssetUUID{}, updateErr
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
		log.Printf("Error checking for existing asset: %v", result.Error)
		return domain.AssetUUID{}, result.Error
	}

	// No existing asset found, create a new one
	assetRecord := types.Asset{
		ID:          asset.ID.String(),
		Name:        &asset.Name,
		Domain:      &asset.Domain,
		Hostname:    asset.Hostname,
		IPAddress:   asset.IP,
		OSName:      &asset.OSName,
		OSVersion:   &asset.OSVersion,
		Type:        asset.Type,
		Description: &asset.Description,
		CreatedAt:   asset.CreatedAt,
		UpdatedAt:   &asset.UpdatedAt,
	}

	err := r.db.WithContext(ctx).Table("assets").Create(&assetRecord).Error
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") && strings.Contains(err.Error(), "idx_assets_ip_address") {
			log.Printf("Duplicate IP detected during creation, trying to update instead: %s", asset.IP)

			// Try to get the existing record again
			var retryAsset types.Asset
			retryResult := r.db.WithContext(ctx).Table("assets").Where("ip_address = ?", asset.IP).First(&retryAsset)

			if retryResult.Error == nil {
				// Update the existing asset
				now := time.Now()
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

				updateErr := r.db.WithContext(ctx).Table("assets").Where("id = ?", retryAsset.ID).Updates(updates).Error
				if updateErr != nil {
					log.Printf("Error updating asset in retry: %v", updateErr)
					return domain.AssetUUID{}, updateErr
				}

				// Return the existing asset ID as UUID
				existingID, parseErr := domain.AssetUUIDFromString(retryAsset.ID)
				if parseErr != nil {
					log.Printf("Error parsing existing asset UUID in retry: %v", parseErr)
					return domain.AssetUUID{}, parseErr
				}

				return existingID, nil
			}

			// If we couldn't find the existing record, return the original error
			log.Printf("Could not find duplicate asset in retry: %v", retryResult.Error)
			return domain.AssetUUID{}, err
		}

		log.Printf("Error creating asset: %v", err)
		return domain.AssetUUID{}, err
	}

	log.Printf("Successfully created new asset with ID: %s", asset.ID)
	return asset.ID, nil
}

// Get implements the asset repository Get method
func (r *assetRepository) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	// Existing implementation...
	// This is already in your codebase, just make sure it exists
	return nil, errors.New("not implemented")
}

// GetByID implements the asset repository GetByID method
func (r *assetRepository) GetByID(ctx context.Context, assetID domain.AssetUUID) (*domain.AssetDomain, error) {
	// Existing implementation...
	// This is already in your codebase, just make sure it exists
	return nil, errors.New("not implemented")
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
