package storage

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/utils"
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

// UpdateAssetPorts implements port.Repo.
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

	if err := tx.Table("ports").
		Where("asset_id = ? AND deleted_at IS NULL", assetID.String()).
		Update("deleted_at", time.Now()).Error; err != nil {
		tx.Rollback()
		return err
	}
	log.Printf("Marked existing ports as deleted for asset ID: %s", assetID.String())

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

// Create implements the asset repository Create method without placeholder IPs
func (r *assetRepository) Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	log.Printf("Creating asset with %d IPs and %d ports", len(asset.AssetIPs), len(asset.Ports))

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.Asset{}).
		Where("hostname = ? AND deleted_at IS NULL", asset.Hostname).
		Count(&count).Error; err != nil {
		return domain.AssetUUID{}, err
	}

	if count > 0 {
		log.Printf("Hostname %s already exists", asset.Hostname)
		return domain.AssetUUID{}, domain.ErrHostnameAlreadyExists
	}

	// Filter and validate IPs while preserving MAC addresses
	var validAssetIPs []domain.AssetIP
	for _, assetIP := range asset.AssetIPs {
		// Basic IP validation
		if r.validateIP(assetIP.IP) {
			validAssetIPs = append(validAssetIPs, domain.AssetIP{
				AssetID:    asset.ID.String(),
				IP:         assetIP.IP,
				MACAddress: assetIP.MACAddress,
			})
		} else {
			log.Printf("Filtering out invalid IP format: %s", assetIP.IP)
		}
	}
	asset.AssetIPs = validAssetIPs

	// Create ports for the asset - prepare the port records
	var portRecords []types.Port
	for _, port := range asset.Ports {
		portRecord := mapper.PortDomain2Storage(port)
		portRecord.AssetID = asset.ID.String()
		portRecords = append(portRecords, *portRecord)
	}

	// Convert asset domain to storage model
	assetRecord, assetIPs := mapper.AssetDomain2Storage(asset)

	// Begin transaction
	tx, err := r.beginTransaction(ctx)
	if err != nil {
		return domain.AssetUUID{}, err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Check for existing IPs if we have valid IPs
	if len(validAssetIPs) > 0 {
		// Check if any IPs already exist
		err = r.handleExistingIPs(ctx, tx, asset, validAssetIPs, assetRecord, assetIPs, portRecords)
		if err != nil {
			tx.Rollback()
			if errors.Is(err, domain.ErrIPAlreadyExists) {
				return domain.AssetUUID{}, err
			}
			return domain.AssetUUID{}, err
		}
	} else {
		// No IPs to check, create a completely new asset
		if err := r.createAssetWithTx(tx, assetRecord); err != nil {
			tx.Rollback()
			return domain.AssetUUID{}, err
		}

		// Create ports for the asset
		if err := r.createPortsWithTx(tx, portRecords, asset.ID.String()); err != nil {
			tx.Rollback()
			return domain.AssetUUID{}, err
		}

		// Create asset IPs
		if len(assetIPs) > 0 {
			if err := r.createNewIPs(tx, assetIPs, make(map[string]bool)); err != nil {
				tx.Rollback()
				return domain.AssetUUID{}, err
			}
		} else {
			log.Printf("No valid IPs to create for asset %s", asset.ID)
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		log.Printf("Error committing transaction: %v", err)
		return domain.AssetUUID{}, err
	}

	log.Printf("Successfully created new asset with ID: %s and %d IPs", asset.ID, len(asset.AssetIPs))
	return asset.ID, nil
}

// validateIP checks if a string is a valid IP address format
func (r *assetRepository) validateIP(ip string) bool {
	// Skip empty IPs
	if ip == "" {
		return false
	}

	// Skip obvious hostnames (no dots, contains non-numeric/dot characters)
	if !strings.Contains(ip, ".") {
		return false
	}

	// Basic IPv4 validation
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
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

// GetByIDs fetches assets by their UUIDs in a single query
// If a single UUID is provided, it returns a slice with one asset
func (r *assetRepository) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	if len(assetUUIDs) == 0 {
		return []domain.AssetDomain{}, nil
	}

	ids := make([]string, len(assetUUIDs))
	for i, uid := range assetUUIDs {
		ids[i] = uid.String()
	}

	var assets []types.Asset
	query := r.db.WithContext(ctx).
		Preload("Ports", "deleted_at IS NULL").
		Preload("VMwareVMs").
		Preload("AssetIPs", "deleted_at IS NULL").
		Where("deleted_at IS NULL")

	if len(assetUUIDs) == 1 {
		err := query.Where("id = ?", assetUUIDs[0]).Find(&assets).Error
		if err != nil {
			return nil, err
		}
	} else {
		err := query.Where("id IN ?", ids).Find(&assets).Error
		if err != nil {
			return nil, err
		}
	}

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	result := make([]domain.AssetDomain, 0, len(assets))
	for _, a := range assets {

		scannerType := scannerTypeMap[a.ID]

		dom, err := mapper.AssetStorage2DomainWithScannerType(a, scannerType)
		if err != nil {
			continue
		}
		result = append(result, *dom)
	}
	return result, nil
}

// Get retrieves assets based on filters
func (r *assetRepository) Get(ctx context.Context, assetFilter domain.AssetFilters) ([]domain.AssetDomain, error) {
	query := r.db.WithContext(ctx).Table("assets").Where("assets.deleted_at IS NULL")

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
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL").
			Where("asset_ips.ip_address LIKE ?", "%"+assetFilter.IP+"%")
	}

	var assets []types.Asset
	if err := query.Find(&assets).Error; err != nil {
		return nil, err
	}

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	// Convert to domain models
	var domainResults []domain.AssetDomain
	for _, asset := range assets {
		// Get IPs for this asset
		_, err := r.getAssetIPs(ctx, asset.ID)
		if err != nil {
			continue
		}

		scannerType := scannerTypeMap[asset.ID]

		// Convert to domain model with scanner type
		assetDomain, err := mapper.AssetStorage2DomainWithScannerType(asset, scannerType)
		if err != nil {
			continue
		}

		domainResults = append(domainResults, *assetDomain)
	}

	return domainResults, nil
}

// Get implements the asset repository Get method with filtering, sorting, and pagination
func (r *assetRepository) GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	var assets []types.Asset
	var total int64

	// Create base query without table() to allow preloading
	query := r.db.WithContext(ctx).Model(&types.Asset{})
	query = applyAssetFilters(r.db, query, assetFilter)

	query = query.Where("assets.deleted_at IS NULL")

	countQuery := r.db.WithContext(ctx).Model(&types.Asset{})
	countQuery = applyAssetFilters(r.db, countQuery, assetFilter)
	countQuery = countQuery.Where("assets.deleted_at IS NULL")

	// Check if any sort options require joins that would affect count
	requiresDistinctCount := false
	for _, sort := range sortOptions {
		columnMapping := mapFieldToDBColumn(sort.Field)
		if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
			requiresDistinctCount = true
			break
		}
	}

	if requiresDistinctCount {
		err := countQuery.Select("DISTINCT assets.id").Count(&total).Error
		if err != nil {
			return nil, 0, err
		}
	} else {
		err := countQuery.Count(&total).Error
		if err != nil {
			return nil, 0, err
		}
	}

	// Apply sorting if provided
	appliedJoins := make(map[string]bool)
	if len(sortOptions) > 0 {
		for _, sort := range sortOptions {
			columnMapping := mapFieldToDBColumn(sort.Field)

			if columnMapping.RequiresJoin && !appliedJoins[columnMapping.Table] {
				query = query.Joins(columnMapping.JoinQuery)
				appliedJoins[columnMapping.Table] = true
			}

			orderDir := "ASC"
			if sort.Order == "desc" {
				orderDir = "DESC"
			}

			if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
				// Use MIN/MAX to handle multiple related records for consistent sorting
				// This ensures deterministic results when an asset has multiple IPs, VMs, or scan jobs
				if orderDir == "ASC" {
					query = query.Order("MIN(" + columnMapping.Column + ") " + orderDir)
				} else {
					query = query.Order("MAX(" + columnMapping.Column + ") " + orderDir)
				}
				// Group by assets.id to handle multiple related records
				query = query.Group("assets.id")
			} else {
				query = query.Order(columnMapping.Column + " " + orderDir)
			}
		}
	}

	hasGroupBy := false
	for _, sort := range sortOptions {
		columnMapping := mapFieldToDBColumn(sort.Field)
		if columnMapping.RequiresJoin && (columnMapping.Table == "asset_ips" || columnMapping.Table == "vmware_vms" || columnMapping.Table == "scanners") {
			hasGroupBy = true
			break
		}
	}

	if hasGroupBy {
		query = query.Select("assets.*")
	} else {
		query = query.Preload("Ports", "deleted_at IS NULL").Preload("VMwareVMs").Preload("AssetIPs", "deleted_at IS NULL")
	}

	// Apply pagination only when limits are set
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&assets).Error
	if err != nil {
		return nil, 0, err
	}

	// If we had GROUP BY, we need to manually load related data for the assets
	if hasGroupBy && len(assets) > 0 {
		assetIDs := make([]string, len(assets))
		for i, asset := range assets {
			assetIDs[i] = asset.ID
		}

		// Load ports separately
		var ports []types.Port
		err = r.db.WithContext(ctx).Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).Find(&ports).Error
		if err != nil {
			return nil, 0, err
		}

		// Load VMware VMs separately
		var vmwares []types.VMwareVM
		err = r.db.WithContext(ctx).Where("asset_id IN ?", assetIDs).Find(&vmwares).Error
		if err != nil {
			return nil, 0, err
		}

		// Load asset IPs separately
		var assetIPs []types.AssetIP
		err = r.db.WithContext(ctx).Where("asset_id IN ? AND deleted_at IS NULL", assetIDs).Find(&assetIPs).Error
		if err != nil {
			return nil, 0, err
		}

		// Map the related data back to assets
		portMap := make(map[string][]types.Port)
		for _, port := range ports {
			portMap[port.AssetID] = append(portMap[port.AssetID], port)
		}

		vmwareMap := make(map[string][]types.VMwareVM)
		for _, vm := range vmwares {
			vmwareMap[vm.AssetID] = append(vmwareMap[vm.AssetID], vm)
		}

		ipMap := make(map[string][]types.AssetIP)
		for _, ip := range assetIPs {
			ipMap[ip.AssetID] = append(ipMap[ip.AssetID], ip)
		}

		// Assign the related data to assets
		for i := range assets {
			assets[i].Ports = portMap[assets[i].ID]
			assets[i].VMwareVMs = vmwareMap[assets[i].ID]
			assets[i].AssetIPs = ipMap[assets[i].ID]
		}
	}

	assetIDs := make([]string, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID
	}

	scannerTypeMap := r.getScannerTypes(ctx, assetIDs)

	// Process the assets with their preloaded relationships
	result := make([]domain.AssetDomain, 0, len(assets))
	for _, asset := range assets {
		scannerType := scannerTypeMap[asset.ID]

		domainAsset, err := mapper.AssetStorage2DomainWithScannerType(asset, scannerType)
		if err != nil {
			// Skip this asset if mapping fails
			continue
		}
		result = append(result, *domainAsset)
	}

	return result, int(total), nil
}

// Update updates an existing asset along with its ports and IPs
func (r *assetRepository) Update(ctx context.Context, asset domain.AssetDomain) error {
	log.Printf("Updating asset with ID: %s, with %d ports and %d IPs", asset.ID, len(asset.Ports), len(asset.AssetIPs))

	var count int64
	if err := r.db.WithContext(ctx).Model(&types.Asset{}).
		Where("hostname = ? AND id != ? AND deleted_at IS NULL", asset.Hostname, asset.ID.String()).
		Count(&count).Error; err != nil {
		return err
	}

	if count > 0 {
		log.Printf("Hostname %s already exists for another asset", asset.Hostname)
		return domain.ErrHostnameAlreadyExists
	}

	// Filter and validate IPs while preserving MAC addresses
	var validAssetIPs []domain.AssetIP
	for i, assetIP := range asset.AssetIPs {
		log.Printf("Original asset IP %d: %s with MAC: %s", i, assetIP.IP, assetIP.MACAddress)
		// Basic IP validation
		if r.validateIP(assetIP.IP) {
			validAssetIPs = append(validAssetIPs, domain.AssetIP{
				AssetID:    asset.ID.String(),
				IP:         assetIP.IP,
				MACAddress: assetIP.MACAddress,
			})
		} else {
			log.Printf("Filtering out invalid IP format: %s", assetIP.IP)
		}
	}
	asset.AssetIPs = validAssetIPs

	a, assetIPPtrs := mapper.AssetDomain2Storage(asset)

	// Begin a transaction
	tx, err := r.beginTransaction(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Get current IPs for this asset
	var currentIPs []types.AssetIP
	if err := tx.Table("asset_ips").
		Where("asset_id = ? AND deleted_at IS NULL", asset.ID.String()).
		Find(&currentIPs).Error; err != nil {
		tx.Rollback()
		return err
	}

	log.Printf("Found %d current active IPs for asset %s", len(currentIPs), asset.ID.String())

	currentIPMap := make(map[string]types.AssetIP)
	for _, ip := range currentIPs {
		currentIPMap[ip.IPAddress] = ip
		log.Printf("Current active IP: %s with ID: %s", ip.IPAddress, ip.ID)
	}

	newIPMap := make(map[string]bool)
	for _, ip := range validAssetIPs {
		newIPMap[ip.IP] = true
		log.Printf("New IP from request: %s", ip.IP)
	}

	// Identify IPs that need to be marked as deleted (they exist in current but not in new)
	var ipsToDelete []types.AssetIP
	for ipAddr, assetIP := range currentIPMap {
		if _, exists := newIPMap[ipAddr]; !exists {
			ipsToDelete = append(ipsToDelete, assetIP)
			log.Printf("Marking IP for deletion: %s with ID: %s", ipAddr, assetIP.ID)
		}
	}

	// Identify new IPs that need to be added (they exist in new but not in current)
	var ipsToAdd []domain.AssetIP
	for _, assetIP := range validAssetIPs {
		if _, exists := currentIPMap[assetIP.IP]; !exists {
			ipsToAdd = append(ipsToAdd, assetIP)
			log.Printf("Marking IP for addition: %s", assetIP.IP)
		}
	}

	// Check if any IP changes are needed
	ipsChanged := len(ipsToDelete) > 0 || len(ipsToAdd) > 0

	if ipsChanged {
		log.Printf("IPs have changed, processing IP changes (delete: %d, add: %d)", len(ipsToDelete), len(ipsToAdd))

		if len(ipsToDelete) > 0 {
			var idsToDelete []string
			for _, ip := range ipsToDelete {
				idsToDelete = append(idsToDelete, ip.ID)
				log.Printf("Marking IP %s as deleted for asset %s", ip.IPAddress, asset.ID.String())
			}

			if err := tx.Table("asset_ips").
				Where("id IN ?", idsToDelete).
				Update("deleted_at", time.Now()).Error; err != nil {
				tx.Rollback()
				log.Printf("Error marking IPs as deleted: %v", err)
				return err
			}
			log.Printf("Marked %d existing IPs as deleted for asset ID: %s", len(ipsToDelete), asset.ID)
		}

		// Only process new IPs if there are any to add
		if len(ipsToAdd) > 0 {
			var newIPAddresses []string
			for _, ip := range ipsToAdd {
				newIPAddresses = append(newIPAddresses, ip.IP)
			}

			// Find any existing IPs in the database (both active and deleted)
			existingActiveIPs, existingDeletedIPs, err := r.findExistingIPs(ctx, newIPAddresses)
			if err != nil {
				tx.Rollback()
				return err
			}

			// Filter out active IPs that belong to other assets
			var conflictActiveIPs []types.AssetIP
			for _, ip := range existingActiveIPs {
				if ip.AssetID != asset.ID.String() {
					conflictActiveIPs = append(conflictActiveIPs, ip)
				}
			}

			// Check for conflicts with other assets' active IPs
			if len(conflictActiveIPs) > 0 {
				isConflict, err := r.checkActiveIPsAssets(ctx, conflictActiveIPs)
				if err != nil {
					tx.Rollback()
					return err
				}
				if isConflict {
					tx.Rollback()
					return domain.ErrIPAlreadyExists
				}
			}

			// Process deleted IPs that can be undeleted
			processedIPs := make(map[string]bool)

			// Undelete and reassign any deleted IPs
			for _, deletedIP := range existingDeletedIPs {
				processedIPs[deletedIP.IPAddress] = true
				macAddress := r.findMACForIP(deletedIP.IPAddress, validAssetIPs)
				log.Printf("Undeleting IP %s and assigning to asset %s", deletedIP.IPAddress, asset.ID.String())

				if err := r.updateOrUndeleteIP(tx, deletedIP, asset.ID.String(), macAddress); err != nil {
					tx.Rollback()
					return err
				}
			}

			// Filter out IPs that were already processed (undeleted) or already belong to this asset
			var newIPsToCreate []*types.AssetIP
			for _, ipPtr := range assetIPPtrs {
				if ipPtr == nil {
					continue
				}

				// Skip IPs that are already processed or already belong to this asset
				if processedIPs[ipPtr.IPAddress] || currentIPMap[ipPtr.IPAddress].ID != "" {
					continue
				}

				newIPsToCreate = append(newIPsToCreate, ipPtr)
			}

			// Create only truly new IPs (not already existing for any asset)
			if len(newIPsToCreate) > 0 {
				for _, ipPtr := range newIPsToCreate {
					log.Printf("Creating new IP %s for asset %s", ipPtr.IPAddress, asset.ID.String())
					if err := tx.Table("asset_ips").Create(ipPtr).Error; err != nil {
						tx.Rollback()
						log.Printf("Error creating new IP %s: %v", ipPtr.IPAddress, err)
						return err
					}
				}
			}
		}
	} else {
		log.Printf("IPs have not changed, skipping IP processing")
	}

	// Update MAC addresses for existing IPs that remain unchanged
	for _, assetIP := range validAssetIPs {
		if currentIP, exists := currentIPMap[assetIP.IP]; exists {
			// Check if MAC address needs to be updated
			if assetIP.MACAddress != "" && assetIP.MACAddress != currentIP.MACAddress {
				log.Printf("Updating MAC address for IP %s from %s to %s", assetIP.IP, currentIP.MACAddress, assetIP.MACAddress)
				updates := map[string]interface{}{
					"mac_address": assetIP.MACAddress,
					"updated_at":  time.Now(),
				}
				if err := tx.Table("asset_ips").
					Where("id = ?", currentIP.ID).
					Updates(updates).Error; err != nil {
					tx.Rollback()
					log.Printf("Error updating MAC address for IP %s: %v", assetIP.IP, err)
					return err
				}
			}
		}
	}

	// Update the asset record
	if err := tx.Table("assets").
		Where("id = ?", a.ID).
		Updates(a).Error; err != nil {
		tx.Rollback()
		log.Printf("Error updating asset record: %v", err)
		return err
	}
	log.Printf("Successfully updated asset record for ID: %s", a.ID)

	var currentPorts []types.Port
	if err := tx.Table("ports").
		Where("asset_id = ? AND deleted_at IS NULL", a.ID).
		Find(&currentPorts).Error; err != nil {
		tx.Rollback()
		log.Printf("Error getting current ports: %v", err)
		return err
	}
	log.Printf("Found %d current active ports for asset %s", len(currentPorts), a.ID)

	// If no ports in the update, mark all existing ports as deleted
	if len(asset.Ports) == 0 {
		if len(currentPorts) > 0 {
			// Soft delete all existing ports
			if err := tx.Table("ports").
				Where("asset_id = ? AND deleted_at IS NULL", a.ID).
				Update("deleted_at", time.Now()).Error; err != nil {
				tx.Rollback()
				log.Printf("Error marking ports as deleted: %v", err)
				return err
			}
			log.Printf("Marked all existing ports as deleted for asset ID: %s", a.ID)
		}
	} else {
		updatePortIDs := make(map[string]bool)
		for _, port := range asset.Ports {
			if port.ID != "" {
				updatePortIDs[port.ID] = true
			}
		}

		if len(currentPorts) > 0 {
			if len(updatePortIDs) > 0 {
				var idsToKeep []string
				for id := range updatePortIDs {
					idsToKeep = append(idsToKeep, id)
				}

				if err := tx.Table("ports").
					Where("asset_id = ? AND deleted_at IS NULL AND id NOT IN ?", a.ID, idsToKeep).
					Update("deleted_at", time.Now()).Error; err != nil {
					tx.Rollback()
					log.Printf("Error marking ports as deleted: %v", err)
					return err
				}
				log.Printf("Marked ports not in update list as deleted for asset ID: %s", a.ID)
			} else {
				if err := tx.Table("ports").
					Where("asset_id = ? AND deleted_at IS NULL", a.ID).
					Update("deleted_at", time.Now()).Error; err != nil {
					tx.Rollback()
					log.Printf("Error marking existing ports as deleted: %v", err)
					return err
				}
				log.Printf("No port IDs provided, marked all existing ports as deleted for asset ID: %s", a.ID)
			}
		}

		for _, port := range asset.Ports {
			portRecord := mapper.PortDomain2Storage(port)
			portRecord.AssetID = a.ID

			if portRecord.ID != "" {
				var existingPort types.Port
				result := tx.Where("id = ? AND asset_id = ?", portRecord.ID, a.ID).First(&existingPort)

				if result.Error == nil {

					if result := tx.Model(&existingPort).Updates(port); result.Error != nil {
						tx.Rollback()
						log.Printf("Error updating port: %v", result.Error)
						return result.Error
					}
					log.Printf("Updated existing port ID: %s for asset ID: %s", portRecord.ID, a.ID)
				} else if result.Error == gorm.ErrRecordNotFound {
					if err := tx.Create(portRecord).Error; err != nil {
						tx.Rollback()
						log.Printf("Error creating port: %v", err)
						return err
					}
					log.Printf("Port ID provided but not found, created new port with ID: %s for asset ID: %s", portRecord.ID, a.ID)
				} else {
					tx.Rollback()
					log.Printf("Error checking if port exists: %v", result.Error)
					return result.Error
				}
			} else {
				portRecord.ID = uuid.New().String()
				if err := tx.Create(portRecord).Error; err != nil {
					tx.Rollback()
					log.Printf("Error creating new port: %v", err)
					return err
				}
				log.Printf("Created new port with ID: %s for asset ID: %s", portRecord.ID, a.ID)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		log.Printf("Error committing transaction: %v", err)
		return err
	}

	log.Printf("Successfully updated asset %s with all associated data", asset.ID)
	return nil
}

// LinkAssetToScanJob links an asset to a scan job record
func (r *assetRepository) LinkAssetToScanJob(ctx context.Context, assetID domain.AssetUUID, scanJobID int64) error {
	log.Printf("Linking asset %s to scan job %d", assetID.String(), scanJobID)

	// Create an AssetScanJob record
	assetScanJob := types.AssetScanJob{
		AssetID:      assetID.String(),
		ScanJobID:    scanJobID,
		DiscoveredAt: time.Now(),
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

// StoreVMwareVM stores VMware VM data in the database
func (r *assetRepository) StoreVMwareVM(ctx context.Context, vmData domain.VMwareVM) error {
	log.Printf("Storing VMware VM data for VM %s (Asset ID: %s)", vmData.VMName, vmData.AssetID)

	// Convert domain VMwareVM to storage VMwareVM
	storageVM := types.VMwareVM{
		VMID:         vmData.VMID,
		AssetID:      vmData.AssetID,
		VMName:       vmData.VMName,
		Hypervisor:   vmData.Hypervisor,
		CPUCount:     vmData.CPUCount,
		MemoryMB:     vmData.MemoryMB,
		DiskSizeGB:   vmData.DiskSizeGB,
		PowerState:   vmData.PowerState,
		LastSyncedAt: vmData.LastSyncedAt,
	}

	// Check if VM already exists
	var count int64
	if err := r.db.WithContext(ctx).Table("vmware_vms").Where("vm_id = ?", vmData.VMID).Count(&count).Error; err != nil {
		log.Printf("Error checking if VM exists: %v", err)
		return err
	}

	// Insert or update based on existence
	if count > 0 {
		// Update existing record
		log.Printf("Updating existing VM record for %s", vmData.VMName)
		return r.db.WithContext(ctx).Table("vmware_vms").
			Where("vm_id = ?", vmData.VMID).
			Updates(map[string]interface{}{
				"asset_id":       vmData.AssetID,
				"vm_name":        vmData.VMName,
				"hypervisor":     vmData.Hypervisor,
				"cpu_count":      int(vmData.CPUCount),
				"memory_mb":      int(vmData.MemoryMB),
				"disk_size_gb":   vmData.DiskSizeGB,
				"power_state":    vmData.PowerState,
				"last_synced_at": vmData.LastSyncedAt,
			}).Error
	} else {
		// Insert new record
		log.Printf("Creating new VM record for %s", vmData.VMName)
		return r.db.WithContext(ctx).Table("vmware_vms").Create(&storageVM).Error
	}
}

// applyAssetFiltersToQuery applies filter conditions to a query
func applyAssetFiltersToQuery(query *gorm.DB, filters *domain.AssetFilters) *gorm.DB {
	if filters == nil {
		return query
	}

	if filters.Name != "" {
		query = query.Where("name LIKE ?", "%"+filters.Name+"%")
	}
	if filters.Domain != "" {
		query = query.Where("domain LIKE ?", "%"+filters.Domain+"%")
	}
	if filters.Hostname != "" {
		query = query.Where("hostname LIKE ?", "%"+filters.Hostname+"%")
	}
	if filters.OSName != "" {
		query = query.Where("os_name LIKE ?", "%"+filters.OSName+"%")
	}
	if filters.OSVersion != "" {
		query = query.Where("os_version LIKE ?", "%"+filters.OSVersion+"%")
	}
	if filters.Type != "" {
		query = query.Where("type = ?", filters.Type)
	}
	if filters.IP != "" {
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL").
			Where("asset_ips.ip_address LIKE ?", "%"+filters.IP+"%").
			Group("assets.id")
	}

	return query
}

// applyUUIDCondition applies UUID-based conditions to a query based on exclude flag
func applyUUIDCondition(query *gorm.DB, uuids []domain.AssetUUID, exclude bool) *gorm.DB {
	if len(uuids) == 0 {
		return query
	}

	if exclude {
		return query.Where("assets.id NOT IN ?", uuids)
	}
	return query.Where("assets.id IN ?", uuids)
}

// DeleteAssets is a unified method that handles all asset deletion scenarios
func (r *assetRepository) DeleteAssets(ctx context.Context, params domain.DeleteParams) (int, error) {
	currentTime := time.Now()
	query := r.db.WithContext(ctx).Model(&types.Asset{})

	// Always only delete non-deleted assets
	query = query.Where("deleted_at IS NULL")

	// Case 1: Single asset deletion by UUID
	if params.UUID != nil {
		result := query.Where("id = ?", *params.UUID).
			Update("deleted_at", currentTime)

		if result.Error != nil {
			return 0, result.Error
		}

		return int(result.RowsAffected), nil
	}

	// Use transaction for all other cases to ensure atomicity
	var affectedRows int64
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txQuery := tx.Model(&types.Asset{}).Where("deleted_at IS NULL")

		// Apply filters if they exist
		if params.Filters != nil {
			txQuery = applyAssetFilters(tx, txQuery, *params.Filters)
		}

		// Apply UUID conditions if UUIDs exist
		if len(params.UUIDs) > 0 {
			txQuery = applyUUIDCondition(txQuery, params.UUIDs, params.Exclude)
		}

		result := txQuery.Update("deleted_at", currentTime)
		if result.Error != nil {
			return result.Error
		}

		affectedRows = result.RowsAffected
		return nil
	})

	if err != nil {
		return 0, err
	}

	return int(affectedRows), nil
}

// ExportAssets exports assets based on asset IDs and export type
func (r *assetRepository) ExportAssets(ctx context.Context, assetIDs []domain.AssetUUID, exportType domain.ExportType, selectedColumns []string) (*domain.ExportData, error) {
	exportData := &domain.ExportData{
		Assets:    make([]map[string]interface{}, 0),
		Ports:     make([]map[string]interface{}, 0),
		VMwareVMs: make([]map[string]interface{}, 0),
		AssetIPs:  make([]map[string]interface{}, 0),
	}

	stringIDs := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		stringIDs[i] = id.String()
	}

	// Check if it's "All" assets request
	fetchAll := len(stringIDs) == 0
	query := r.db.WithContext(ctx).Table("assets")

	// Add WHERE clause if we're not fetching all assets
	if !fetchAll {
		query = query.Where("id IN ?", stringIDs)
	}

	// Select columns based on export type
	if exportType == domain.FullExport {
		var assets []map[string]interface{}
		if err := query.Find(&assets).Error; err != nil {
			return nil, err
		}
		exportData.Assets = assets

		portsQuery := r.db.WithContext(ctx).Table("ports").
			Select("ports.*").
			Joins("LEFT JOIN assets ON ports.asset_id = assets.id AND assets.deleted_at IS NULL").
			Where("ports.deleted_at IS NULL")

		if !fetchAll {
			portsQuery = portsQuery.Where("assets.id IN ?", stringIDs)
		}

		if err := portsQuery.Find(&exportData.Ports).Error; err != nil {
			return nil, err
		}

		vmwareQuery := r.db.WithContext(ctx).Table("vmware_vms").
			Select("vmware_vms.*").
			Joins("LEFT JOIN assets ON vmware_vms.asset_id = assets.id AND assets.deleted_at IS NULL")

		if !fetchAll {
			vmwareQuery = vmwareQuery.Where("assets.id IN ?", stringIDs)
		}

		if err := vmwareQuery.Find(&exportData.VMwareVMs).Error; err != nil {
			return nil, err
		}

		ipsQuery := r.db.WithContext(ctx).Table("asset_ips").
			Select("asset_ips.*").
			Joins("LEFT JOIN assets ON asset_ips.asset_id = assets.id AND assets.deleted_at IS NULL").
			Where("asset_ips.deleted_at IS NULL")

		if !fetchAll {
			ipsQuery = ipsQuery.Where("assets.id IN ?", stringIDs)
		}

		if err := ipsQuery.Find(&exportData.AssetIPs).Error; err != nil {
			return nil, err
		}
	} else {
		assetColumns := filterColumnsByTable(selectedColumns, "assets")
		portColumns := filterColumnsByTable(selectedColumns, "ports")
		vmwareColumns := filterColumnsByTable(selectedColumns, "vmware_vms")
		ipColumns := filterColumnsByTable(selectedColumns, "asset_ips")

		// Always include the ID column for assets to ensure proper relationship
		hasIDColumn := false
		for _, col := range assetColumns {
			if col == "id" {
				hasIDColumn = true
				break
			}
		}

		if !hasIDColumn {
			assetColumns = append(assetColumns, "id")
		}

		// Export assets with selected columns
		if len(assetColumns) > 0 {
			if err := query.Select(assetColumns).Find(&exportData.Assets).Error; err != nil {
				return nil, err
			}
		}

		if len(portColumns) > 0 {
			prefixedPortColumns := make([]string, 0, len(portColumns)+1)
			for _, col := range portColumns {
				prefixedPortColumns = append(prefixedPortColumns, "ports."+col)
			}
			prefixedPortColumns = append(prefixedPortColumns, "ports.asset_id")

			portsQuery := r.db.WithContext(ctx).Table("ports").
				Select(strings.Join(prefixedPortColumns, ", ")).
				Joins("LEFT JOIN assets ON ports.asset_id = assets.id AND assets.deleted_at IS NULL").
				Where("ports.deleted_at IS NULL")

			if !fetchAll {
				portsQuery = portsQuery.Where("assets.id IN ?", stringIDs)
			}

			if err := portsQuery.Find(&exportData.Ports).Error; err != nil {
				return nil, err
			}
		}

		if len(vmwareColumns) > 0 {
			prefixedVMColumns := make([]string, 0, len(vmwareColumns)+1)
			for _, col := range vmwareColumns {
				prefixedVMColumns = append(prefixedVMColumns, "vmware_vms."+col)
			}
			prefixedVMColumns = append(prefixedVMColumns, "vmware_vms.asset_id")

			vmwareQuery := r.db.WithContext(ctx).Table("vmware_vms").
				Select(strings.Join(prefixedVMColumns, ", ")).
				Joins("LEFT JOIN assets ON vmware_vms.asset_id = assets.id AND assets.deleted_at IS NULL")

			if !fetchAll {
				vmwareQuery = vmwareQuery.Where("assets.id IN ?", stringIDs)
			}

			if err := vmwareQuery.Find(&exportData.VMwareVMs).Error; err != nil {
				return nil, err
			}
		}

		if len(ipColumns) > 0 {
			prefixedIPColumns := make([]string, 0, len(ipColumns)+1)
			for _, col := range ipColumns {
				prefixedIPColumns = append(prefixedIPColumns, "asset_ips."+col)
			}
			prefixedIPColumns = append(prefixedIPColumns, "asset_ips.asset_id")

			ipsQuery := r.db.WithContext(ctx).Table("asset_ips").
				Select(strings.Join(prefixedIPColumns, ", ")).
				Joins("LEFT JOIN assets ON asset_ips.asset_id = assets.id AND assets.deleted_at IS NULL").
				Where("asset_ips.deleted_at IS NULL")

			if !fetchAll {
				ipsQuery = ipsQuery.Where("assets.id IN ?", stringIDs)
			}

			if err := ipsQuery.Find(&exportData.AssetIPs).Error; err != nil {
				return nil, err
			}
		}
	}

	return exportData, nil
}

// filterColumnsByTable filters the selected columns by table prefix
func filterColumnsByTable(columns []string, tablePrefix string) []string {
	prefix := tablePrefix + "."
	var result []string
	for _, col := range columns {
		if len(col) > len(prefix) && col[:len(prefix)] == prefix {
			result = append(result, col[len(prefix):])
		}
	}
	return result
}

// Helper function to apply filters to the query
func applyAssetFilters(baseDB *gorm.DB, query *gorm.DB, assetFilter domain.AssetFilters) *gorm.DB {
	if utils.HasFilterValues(assetFilter.Name) {
		names := utils.SplitAndTrim(assetFilter.Name)
		if len(names) > 0 {
			subQuery := query.Where("assets.name LIKE ?", "%"+names[0]+"%")
			for i := 1; i < len(names); i++ {
				subQuery = subQuery.Or("assets.name LIKE ?", "%"+names[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	// Add the rest of the filter conditions
	if utils.HasFilterValues(assetFilter.Domain) {
		domains := utils.SplitAndTrim(assetFilter.Domain)
		if len(domains) > 0 {
			subQuery := query.Where("assets.domain LIKE ?", "%"+domains[0]+"%")
			for i := 1; i < len(domains); i++ {
				subQuery = subQuery.Or("assets.domain LIKE ?", "%"+domains[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.Hostname) {
		hostnames := utils.SplitAndTrim(assetFilter.Hostname)
		if len(hostnames) > 0 {
			subQuery := query.Where("assets.hostname LIKE ?", "%"+hostnames[0]+"%")
			for i := 1; i < len(hostnames); i++ {
				subQuery = subQuery.Or("assets.hostname LIKE ?", "%"+hostnames[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.OSName) {
		osNames := utils.SplitAndTrim(assetFilter.OSName)
		if len(osNames) > 0 {
			subQuery := query.Where("assets.os_name LIKE ?", "%"+osNames[0]+"%")
			for i := 1; i < len(osNames); i++ {
				subQuery = subQuery.Or("assets.os_name LIKE ?", "%"+osNames[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.OSVersion) {
		osVersions := utils.SplitAndTrim(assetFilter.OSVersion)
		if len(osVersions) > 0 {
			subQuery := query.Where("assets.os_version LIKE ?", "%"+osVersions[0]+"%")
			for i := 1; i < len(osVersions); i++ {
				subQuery = subQuery.Or("assets.os_version LIKE ?", "%"+osVersions[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.Type) {
		types := utils.SplitAndTrim(assetFilter.Type)
		if len(types) > 0 {
			subQuery := query.Where("assets.asset_type = ?", types[0])
			for i := 1; i < len(types); i++ {
				subQuery = subQuery.Or("assets.asset_type = ?", types[i])
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.IP) {
		query = query.Joins("JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL").
			Where("asset_ips.ip_address LIKE ?", "%"+assetFilter.IP+"%").
			Group("assets.id")
	}

	// Handle scanner type filter
	if utils.HasFilterValues(assetFilter.ScannerType) {
		scannerTypes := utils.SplitAndTrim(assetFilter.ScannerType)
		if len(scannerTypes) > 0 {
			// Join with asset_scan_jobs and scan_jobs tables to filter by scanner type
			subQuery := baseDB.Table("asset_scan_jobs asj").
				Select("asj.asset_id").
				Joins("JOIN scan_jobs ON asj.scan_job_id = scan_jobs.id").
				Joins("JOIN scanners ON scan_jobs.scanner_id = scanners.id").
				Where("scanners.scan_type IN ?", scannerTypes).
				Group("asj.asset_id")

			query = query.Where("assets.id IN (?)", subQuery)
		}
	}

	// Handle network filter
	if utils.HasFilterValues(assetFilter.Network) {
		networks := utils.SplitAndTrim(assetFilter.Network)
		if len(networks) > 0 {
			var assetIPsList utils.AssetIPsList

			if err := baseDB.WithContext(context.Background()).
				Table("asset_ips").
				Select("asset_id, ip_address").
				Where("deleted_at IS NULL").
				Find(&assetIPsList).Error; err != nil {

				log.Printf("Error fetching asset IPs: %v", err)
				return query
			}

			matchingAssetIDs, _ := utils.IpsInNetwork(networks, assetIPsList)

			ids := make([]string, 0, len(matchingAssetIDs))
			if len(matchingAssetIDs) > 0 {
				for id := range matchingAssetIDs {
					ids = append(ids, id)
				}
			}
			query = query.Where("assets.id IN (?)", ids)
		}
	}

	return query
}

// ColumnMapping represents a database column mapping with metadata
type ColumnMapping struct {
	Column       string
	Table        string
	RequiresJoin bool
	JoinType     string
	JoinQuery    string
}

// TableJoinConfig holds join configuration for a table
type TableJoinConfig struct {
	Table     string
	JoinQuery string
	JoinType  string
}

var (
	// Join configurations for different tables
	joinConfigs = map[string]TableJoinConfig{
		"asset_ips": {
			Table:     "asset_ips",
			JoinQuery: "LEFT JOIN asset_ips ON assets.id = asset_ips.asset_id AND asset_ips.deleted_at IS NULL",
			JoinType:  "LEFT",
		},
		"vmware_vms": {
			Table:     "vmware_vms",
			JoinQuery: "LEFT JOIN vmware_vms ON assets.id = vmware_vms.asset_id",
			JoinType:  "LEFT",
		},
		"scanners": {
			Table: "scanners",
			JoinQuery: `LEFT JOIN asset_scan_jobs asj ON assets.id = asj.asset_id
						LEFT JOIN scan_jobs sj ON asj.scan_job_id = sj.id  
						LEFT JOIN scanners ON sj.scanner_id = scanners.id`,
			JoinType: "LEFT",
		},
	}

	// Scanner field mappings - these need special mapping
	scannerFieldMappings = map[string]string{
		"scanner.type": "scanners.scan_type",
	}

	// Assets table fields - just field names, columns are auto-generated
	assetFields = []string{
		"name", "domain", "hostname", "os_name", "os_version", "type",
		"description", "created_at", "updated_at", "logging_completed",
		"asset_value", "risk",
	}
)

// Helper function to map request field names to database column names with join information
func mapFieldToDBColumn(field string) ColumnMapping {
	// Handle scanner fields with special mapping
	if column, exists := scannerFieldMappings[field]; exists {
		return ColumnMapping{
			Column:       column,
			Table:        "scanners",
			RequiresJoin: true,
			JoinType:     joinConfigs["scanners"].JoinType,
			JoinQuery:    joinConfigs["scanners"].JoinQuery,
		}
	}

	// Check if it's a table-prefixed field (like "asset_ips.ip_address" or "vmware_vms.vm_name")
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		if len(parts) == 2 {
			tableName := parts[0]
			columnName := parts[1]

			// For prefixed fields, the key equals the column (pattern you noticed)
			fullColumn := tableName + "." + columnName

			if joinConfig, exists := joinConfigs[tableName]; exists {
				return ColumnMapping{
					Column:       fullColumn,
					Table:        tableName,
					RequiresJoin: true,
					JoinType:     joinConfig.JoinType,
					JoinQuery:    joinConfig.JoinQuery,
				}
			}
		}
	}

	// Check if it's an assets table field
	for _, assetField := range assetFields {
		if field == assetField {
			columnName := field
			return ColumnMapping{
				Column: "assets." + columnName,
				Table:  "assets",
			}
		}
	}

	// Default fallback
	return ColumnMapping{Column: "assets.created_at", Table: "assets"}
}

// GetDistinctOSNames returns a list of distinct OS names from all assets
func (r *assetRepository) GetDistinctOSNames(ctx context.Context) ([]string, error) {
	var osNames []string

	err := r.db.WithContext(ctx).
		Model(&types.Asset{}).
		Select("DISTINCT os_name").
		Where("os_name IS NOT NULL AND os_name != ''").
		Order("os_name ASC").
		Pluck("os_name", &osNames).Error

	if err != nil {
		return nil, err
	}

	return osNames, nil
}

// createAssetWithTx creates an asset record in a transaction
func (r *assetRepository) createAssetWithTx(tx *gorm.DB, assetRecord *types.Asset) error {
	if err := tx.Table("assets").Create(assetRecord).Error; err != nil {
		log.Printf("Error creating asset: %v", err)
		return err
	}
	return nil
}

// createPortsWithTx creates port records for an asset in a transaction
func (r *assetRepository) createPortsWithTx(tx *gorm.DB, ports []types.Port, assetID string) error {
	for _, port := range ports {
		port.AssetID = assetID
		if err := tx.Table("ports").Create(&port).Error; err != nil {
			log.Printf("Error creating port %d/%s for asset: %v",
				port.PortNumber, port.Protocol, err)
			return err
		}
	}

	if len(ports) > 0 {
		log.Printf("Created %d ports for asset %s", len(ports), assetID)
	}
	return nil
}

// updateOrUndeleteIP updates an existing IP record, optionally undeleting it
func (r *assetRepository) updateOrUndeleteIP(tx *gorm.DB, foundIP types.AssetIP, newAssetID string, macAddress string) error {
	now := time.Now()
	updates := map[string]interface{}{
		"asset_id":   newAssetID,
		"updated_at": now,
	}

	// If the IP is deleted, undelete it
	if foundIP.DeletedAt != nil {
		updates["deleted_at"] = nil
		log.Printf("Undeleting IP %s and assigning to new asset %s", foundIP.IPAddress, newAssetID)
	} else {
		log.Printf("Reassigning existing IP %s to new asset %s", foundIP.IPAddress, newAssetID)
	}

	// Update MAC address if provided
	if macAddress != "" {
		updates["mac_address"] = macAddress
	}

	// Update the IP record
	if err := tx.Table("asset_ips").Where("id = ?", foundIP.ID).Updates(updates).Error; err != nil {
		log.Printf("Error updating IP %s: %v", foundIP.IPAddress, err)
		return err
	}

	return nil
}

// createNewIPs creates new IP records in a transaction
func (r *assetRepository) createNewIPs(tx *gorm.DB, assetIPs []*types.AssetIP, processedIPs map[string]bool) error {
	for _, assetIPPtr := range assetIPs {
		if assetIPPtr == nil {
			continue
		}

		if !processedIPs[assetIPPtr.IPAddress] {
			if err := tx.Table("asset_ips").Create(assetIPPtr).Error; err != nil {
				log.Printf("Error creating new IP %s: %v", assetIPPtr.IPAddress, err)
				return err
			}
			log.Printf("Created new IP %s for asset %s", assetIPPtr.IPAddress, assetIPPtr.AssetID)
		}
	}
	return nil
}

// findExistingIPs finds existing IPs for a list of IP addresses and categorizes them
func (r *assetRepository) findExistingIPs(ctx context.Context, ipAddresses []string) ([]types.AssetIP, []types.AssetIP, error) {
	var foundIPs []types.AssetIP
	if err := r.db.WithContext(ctx).Table("asset_ips").Where("ip_address IN ?", ipAddresses).Find(&foundIPs).Error; err != nil {
		log.Printf("Error checking for existing IPs: %v", err)
		return nil, nil, err
	}

	// Separate into deleted and non-deleted IPs
	var existingActiveIPs []types.AssetIP
	var existingDeletedIPs []types.AssetIP

	for _, ip := range foundIPs {
		if ip.DeletedAt == nil {
			existingActiveIPs = append(existingActiveIPs, ip)
		} else {
			existingDeletedIPs = append(existingDeletedIPs, ip)
		}
	}

	return existingActiveIPs, existingDeletedIPs, nil
}

// checkActiveIPsAssets checks if active IPs belong to non-deleted assets
func (r *assetRepository) checkActiveIPsAssets(ctx context.Context, activeIPs []types.AssetIP) (bool, error) {
	if len(activeIPs) == 0 {
		return false, nil
	}

	// Get the first active IP to check its asset
	activeIP := activeIPs[0]

	var existingAsset types.Asset
	if err := r.db.WithContext(ctx).Table("assets").Where("id = ?", activeIP.AssetID).First(&existingAsset).Error; err != nil {
		log.Printf("Error finding existing asset for IP %s: %v", activeIP.IPAddress, err)
		return false, err
	}

	// If the asset is not deleted, return true indicating IP conflict
	if existingAsset.DeletedAt == nil {
		log.Printf("Asset with IP %s already exists and is not deleted (Asset ID: %s)", activeIP.IPAddress, existingAsset.ID)
		return true, nil
	}

	// Asset is deleted but IP is not
	log.Printf("Found active IP(s) belonging to deleted asset(s), will create new asset and reassign IPs")
	return false, nil
}

// findMACForIP finds MAC address for a given IP in the list of valid asset IPs
func (r *assetRepository) findMACForIP(ip string, validAssetIPs []domain.AssetIP) string {
	for _, assetIP := range validAssetIPs {
		if assetIP.IP == ip && assetIP.MACAddress != "" {
			return assetIP.MACAddress
		}
	}
	return ""
}

// beginTransaction begins a database transaction
func (r *assetRepository) beginTransaction(ctx context.Context) (*gorm.DB, error) {
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	return tx, nil
}

// handleExistingIPs checks and processes existing IPs when creating a new asset
func (r *assetRepository) handleExistingIPs(ctx context.Context, tx *gorm.DB, asset domain.AssetDomain,
	validAssetIPs []domain.AssetIP, assetRecord *types.Asset, assetIPs []*types.AssetIP, portRecords []types.Port) error {

	// Collect all IP addresses to check
	var ipAddresses []string
	for _, ip := range validAssetIPs {
		ipAddresses = append(ipAddresses, ip.IP)
	}

	// Find any existing IPs in the database
	existingActiveIPs, existingDeletedIPs, err := r.findExistingIPs(ctx, ipAddresses)
	if err != nil {
		return err
	}

	// If any non-deleted IPs exist, check if they belong to a non-deleted asset
	if len(existingActiveIPs) > 0 {
		isConflict, err := r.checkActiveIPsAssets(ctx, existingActiveIPs)
		if err != nil {
			return err
		}
		if isConflict {
			return domain.ErrIPAlreadyExists
		}
	}

	// Create the asset record
	if err := r.createAssetWithTx(tx, assetRecord); err != nil {
		return err
	}

	// Create ports for the asset
	if err := r.createPortsWithTx(tx, portRecords, asset.ID.String()); err != nil {
		return err
	}

	// Track the IPs we've processed to avoid duplicates
	processedIPs := make(map[string]bool)

	// First, handle all active IPs (belonging to deleted assets)
	for _, foundIP := range existingActiveIPs {
		processedIPs[foundIP.IPAddress] = true

		// Find MAC address for this IP in our valid asset IPs
		macAddress := r.findMACForIP(foundIP.IPAddress, validAssetIPs)

		// Update the IP record with asset ID and possibly MAC address
		if err := r.updateOrUndeleteIP(tx, foundIP, asset.ID.String(), macAddress); err != nil {
			return err
		}
	}

	// Then handle deleted IPs that need to be undeleted
	for _, foundIP := range existingDeletedIPs {
		processedIPs[foundIP.IPAddress] = true

		// Find MAC address for this IP in our valid asset IPs
		macAddress := r.findMACForIP(foundIP.IPAddress, validAssetIPs)

		// Undelete the IP record and update with asset ID and MAC address
		if err := r.updateOrUndeleteIP(tx, foundIP, asset.ID.String(), macAddress); err != nil {
			return err
		}
	}

	// Finally, create any new IPs that weren't found in the database
	if err := r.createNewIPs(tx, assetIPs, processedIPs); err != nil {
		return err
	}

	log.Printf("Successfully processed existing IPs and created new ones for asset %s", asset.ID)
	return nil
}

func (r *assetRepository) getScannerTypes(ctx context.Context, assetIDs []string) map[string]string {
	scannerTypeMap := make(map[string]string)

	if len(assetIDs) > 0 {
		type ScannerTypeResult struct {
			AssetID  string `gorm:"column:asset_id"`
			ScanType string `gorm:"column:scan_type"`
		}

		var results []ScannerTypeResult

		latestScanJobSubquery := r.db.WithContext(ctx).
			Table("asset_scan_jobs asj1").
			Select("asj1.asset_id, MAX(asj1.discovered_at) as latest_discovery").
			Where("asj1.asset_id IN ?", assetIDs).
			Group("asj1.asset_id")

		query := r.db.WithContext(ctx).
			Table("asset_scan_jobs asj").
			Select("asj.asset_id, scanners.scan_type").
			Joins("JOIN scan_jobs ON asj.scan_job_id = scan_jobs.id").
			Joins("JOIN scanners ON scan_jobs.scanner_id = scanners.id").
			Joins("JOIN (?) as latest ON asj.asset_id = latest.asset_id AND asj.discovered_at = latest.latest_discovery", latestScanJobSubquery)

		if err := query.Find(&results).Error; err != nil {
			log.Printf("Error getting scanner types for assets: %v", err)
		} else {
			for _, result := range results {
				scannerTypeMap[result.AssetID] = result.ScanType
			}
		}
	}

	return scannerTypeMap
}
