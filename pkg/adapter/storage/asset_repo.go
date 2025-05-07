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

// Create implements the asset repository Create method without placeholder IPs
func (r *assetRepository) Create(ctx context.Context, asset domain.AssetDomain) (domain.AssetUUID, error) {
	log.Printf("Creating asset with %d IPs", len(asset.IPs))

	// Filter and validate IPs
	var validIPs []string
	for _, ip := range asset.IPs {
		// Basic IP validation - check if it looks like an IPv4 address
		if r.validateIP(ip) {
			validIPs = append(validIPs, ip)
		} else {
			log.Printf("Filtering out invalid IP format: %s", ip)
		}
	}

	// Set the valid IPs (could be empty)
	asset.IPs = validIPs

	// If we have valid IPs, check if an asset with the primary IP already exists
	if len(validIPs) > 0 {
		primaryIP := validIPs[0]
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

	// Create asset IPs only if we have valid IPs
	if len(assetIPs) > 0 {
		for _, assetIP := range assetIPs {
			if err := tx.Table("asset_ips").Create(assetIP).Error; err != nil {
				tx.Rollback()
				log.Printf("Error creating asset IP %s: %v", assetIP.IPAddress, err)
				return domain.AssetUUID{}, err
			}
		}
		log.Printf("Created %d IP entries for asset %s", len(assetIPs), asset.ID)
	} else {
		log.Printf("No valid IPs to create for asset %s", asset.ID)
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		log.Printf("Error committing transaction: %v", err)
		return domain.AssetUUID{}, err
	}

	log.Printf("Successfully created new asset with ID: %s and %d IPs", asset.ID, len(asset.IPs))
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

// GetByID retrieves an asset by its ID
func (r *assetRepository) GetByID(ctx context.Context, assetUUID domain.AssetUUID) (*domain.AssetDomain, error) {
	var asset types.Asset
	// Use preload to include related data
	err := r.db.WithContext(ctx).Preload("Ports").Preload("VMwareVMs").Preload("AssetIPs").Where("id = ?", assetUUID).First(&asset).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if asset.ID == "" {
		return nil, nil
	}
	return mapper.AssetStorage2Domain(asset)
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
		_, err := r.getAssetIPs(ctx, asset.ID)
		if err != nil {
			continue
		}

		// Convert to domain model
		assetDomain, err := mapper.AssetStorage2Domain(asset)
		if err != nil {
			continue
		}

		results = append(results, *assetDomain)
	}

	return results, nil
}

// GetByIDs fetches multiple assets by their UUIDs in a single query
func (r *assetRepository) GetByIDs(ctx context.Context, assetUUIDs []domain.AssetUUID) ([]domain.AssetDomain, error) {
	ids := make([]string, len(assetUUIDs))
	for i, uid := range assetUUIDs {
		ids[i] = uid.String()
	}
	var assets []types.Asset
	err := r.db.WithContext(ctx).
		Preload("Ports").
		Preload("VMwareVMs").
		Preload("AssetIPs").
		Where("id IN ?", ids).
		Find(&assets).Error
	if err != nil {
		return nil, err
	}
	result := make([]domain.AssetDomain, 0, len(assets))
	for _, a := range assets {
		dom, err := mapper.AssetStorage2Domain(a)
		if err != nil {
			continue
		}
		result = append(result, *dom)
	}
	return result, nil
}

// Get implements the asset repository Get method with filtering, sorting, and pagination
func (r *assetRepository) GetByFilter(ctx context.Context, assetFilter domain.AssetFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.AssetDomain, int, error) {
	var assets []types.Asset
	var total int64

	// Create base query without table() to allow preloading
	query := r.db.WithContext(ctx).Model(&types.Asset{})
	query = applyAssetFilters(r.db, query, assetFilter)

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// Apply sorting if provided
	if len(sortOptions) > 0 {
		for _, sort := range sortOptions {
			dbField := mapFieldToDBColumn(sort.Field)
			orderDir := "ASC"
			if sort.Order == "desc" {
				orderDir = "DESC"
			}
			query = query.Order(dbField + " " + orderDir)
		}
	}

	// Add preloads for related data
	query = query.Preload("Ports").Preload("VMwareVMs").Preload("AssetIPs")

	// Apply pagination only when limits are set
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err = query.Find(&assets).Error
	if err != nil {
		return nil, 0, err
	}

	// Process the assets with their preloaded relationships
	result := make([]domain.AssetDomain, 0, len(assets))
	for _, asset := range assets {
		domainAsset, err := mapper.AssetStorage2Domain(asset)
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
	a, _ := mapper.AssetDomain2Storage(asset)
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Table("assets").
			Where("id = ?", a.ID).
			Updates(a).Error; err != nil {
			return err
		}

		// Replace ports: delete existing and insert new
		if err := tx.Table("ports").
			Where("asset_id = ?", a.ID).
			Delete(&types.Port{}).Error; err != nil {
			return err
		}

		for _, p := range asset.Ports {
			sp := mapper.PortDomain2Storage(p)
			if err := tx.Table("ports").Create(sp).Error; err != nil {
				return err
			}
		}

		// Replace asset IPs: delete existing and insert new
		if err := tx.Table("asset_ips").
			Where("asset_id = ?", a.ID).
			Delete(&types.AssetIP{}).Error; err != nil {
			return err
		}

		for _, ip := range asset.AssetIPs {
			sip := mapper.AssetIPDomain2Storage(ip)
			if err := tx.Table("asset_ips").Create(sip).Error; err != nil {
				return err
			}
		}

		return nil
	})
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

// Delete soft-deletes an asset by its UUID
func (r *assetRepository) Delete(ctx context.Context, assetUUID domain.AssetUUID) (int, error) {
	currentTime := time.Now()
	result := r.db.WithContext(ctx).
		Model(&types.Asset{}).
		Where("id = ?", assetUUID).
		Update("deleted_at", currentTime)

	if result.Error != nil {
		return 0, result.Error
	}

	if result.RowsAffected == 0 {
		return 0, nil
	}

	return 1, nil
}

// DeleteMultiple soft-deletes multiple assets by their UUIDs
func (r *assetRepository) DeleteMultiple(ctx context.Context, assetUUIDs []domain.AssetUUID) error {
	if len(assetUUIDs) == 0 {
		return nil
	}

	// Use transaction to ensure atomicity for multiple assets deletion
	currentTime := time.Now()
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&types.Asset{}).
			Where("id IN ?", assetUUIDs).
			Update("deleted_at", currentTime).Error; err != nil {
			return err
		}

		return nil
	})
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

		if err := r.db.WithContext(ctx).Table("ports").
			Select("*").
			Joins("LEFT JOIN assets ON ports.asset_id = assets.id").
			Where(fetchAll, "", "assets.id IN ?", stringIDs).
			Find(&exportData.Ports).Error; err != nil {
			return nil, err
		}

		if err := r.db.WithContext(ctx).Table("vmware_vms").
			Select("*").
			Joins("LEFT JOIN assets ON vmware_vms.asset_id = assets.id").
			Where(fetchAll, "", "assets.id IN ?", stringIDs).
			Find(&exportData.VMwareVMs).Error; err != nil {
			return nil, err
		}

		if err := r.db.WithContext(ctx).Table("asset_ips").
			Select("*").
			Joins("LEFT JOIN assets ON asset_ips.asset_id = assets.id").
			Where(fetchAll, "", "assets.id IN ?", stringIDs).
			Find(&exportData.AssetIPs).Error; err != nil {
			return nil, err
		}
	} else {
		assetColumns := filterColumnsByTable(selectedColumns, "assets")
		portColumns := filterColumnsByTable(selectedColumns, "ports")
		vmwareColumns := filterColumnsByTable(selectedColumns, "vmware_vms")
		ipColumns := filterColumnsByTable(selectedColumns, "asset_ips")

		// If no asset columns are selected, at least include the ID
		if len(assetColumns) == 0 {
			assetColumns = []string{"id"}
		}

		// Export assets with selected columns
		if len(assetColumns) > 0 {
			if err := query.Select(assetColumns).Find(&exportData.Assets).Error; err != nil {
				return nil, err
			}
		}

		if len(portColumns) > 0 {
			if err := r.db.WithContext(ctx).Table("ports").
				Select(append(portColumns, "asset_id")).
				Joins("LEFT JOIN assets ON ports.asset_id = assets.id").
				Where(fetchAll, "", "assets.id IN ?", stringIDs).
				Find(&exportData.Ports).Error; err != nil {
				return nil, err
			}
		}

		if len(vmwareColumns) > 0 {
			if err := r.db.WithContext(ctx).Table("vmware_vms").
				Select(append(vmwareColumns, "asset_id")).
				Joins("LEFT JOIN assets ON vmware_vms.asset_id = assets.id").
				Where(fetchAll, "", "assets.id IN ?", stringIDs).
				Find(&exportData.VMwareVMs).Error; err != nil {
				return nil, err
			}
		}

		if len(ipColumns) > 0 {
			if err := r.db.WithContext(ctx).Table("asset_ips").
				Select(append(ipColumns, "asset_id")).
				Joins("LEFT JOIN assets ON asset_ips.asset_id = assets.id").
				Where(fetchAll, "", "assets.id IN ?", stringIDs).
				Find(&exportData.AssetIPs).Error; err != nil {
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
			subQuery := query.Where("name LIKE ?", "%"+names[0]+"%")
			for i := 1; i < len(names); i++ {
				subQuery = subQuery.Or("name LIKE ?", "%"+names[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	// Add the rest of the filter conditions
	if utils.HasFilterValues(assetFilter.Domain) {
		domains := utils.SplitAndTrim(assetFilter.Domain)
		if len(domains) > 0 {
			subQuery := query.Where("domain LIKE ?", "%"+domains[0]+"%")
			for i := 1; i < len(domains); i++ {
				subQuery = subQuery.Or("domain LIKE ?", "%"+domains[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.Hostname) {
		hostnames := utils.SplitAndTrim(assetFilter.Hostname)
		if len(hostnames) > 0 {
			subQuery := query.Where("hostname LIKE ?", "%"+hostnames[0]+"%")
			for i := 1; i < len(hostnames); i++ {
				subQuery = subQuery.Or("hostname LIKE ?", "%"+hostnames[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.OSName) {
		osNames := utils.SplitAndTrim(assetFilter.OSName)
		if len(osNames) > 0 {
			subQuery := query.Where("os_name LIKE ?", "%"+osNames[0]+"%")
			for i := 1; i < len(osNames); i++ {
				subQuery = subQuery.Or("os_name LIKE ?", "%"+osNames[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.OSVersion) {
		osVersions := utils.SplitAndTrim(assetFilter.OSVersion)
		if len(osVersions) > 0 {
			subQuery := query.Where("os_version LIKE ?", "%"+osVersions[0]+"%")
			for i := 1; i < len(osVersions); i++ {
				subQuery = subQuery.Or("os_version LIKE ?", "%"+osVersions[i]+"%")
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.Type) {
		types := utils.SplitAndTrim(assetFilter.Type)
		if len(types) > 0 {
			subQuery := query.Where("asset_type = ?", types[0])
			for i := 1; i < len(types); i++ {
				subQuery = subQuery.Or("asset_type = ?", types[i])
			}
			query = query.Where(subQuery)
		}
	}

	if utils.HasFilterValues(assetFilter.IP) {
		ips := utils.SplitAndTrim(assetFilter.IP)
		if len(ips) > 0 {
			subQuery := baseDB.Table("asset_ips").Select("asset_id").Where("ip_address LIKE ?", "%"+ips[0]+"%")
			for i := 1; i < len(ips); i++ {
				subQuery = subQuery.Or("ip_address LIKE ?", "%"+ips[i]+"%")
			}
			query = query.Where("id IN (?)", subQuery)
		}
	}

	return query
}

// Helper function to map request field names to database column names
func mapFieldToDBColumn(field string) string {
	// Map API field names to database column names
	switch field {
	case "name":
		return "name"
	case "domain":
		return "domain"
	case "hostname":
		return "hostname"
	case "os_name":
		return "os_name"
	case "os_version":
		return "os_version"
	case "type":
		return "asset_type"
	case "ip":
		return "ip_address"
	case "description":
		return "description"
	case "created_at":
		return "created_at"
	case "updated_at":
		return "updated_at"
	default:
		return "created_at"
	}
}
