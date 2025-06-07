package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/query"
	"gorm.io/gorm"
)

type scannerRepo struct {
	db *gorm.DB
}

// UpdateAllEnabled implements port.Repo by updating the status of all scanners
func (r *scannerRepo) UpdateAllEnabled(ctx context.Context, status bool) (int, error) {
	log.Printf("Repository: Updating all scanners to status=%v", status)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Using GORM to update all non-deleted scanners at once
	now := time.Now()
	result := db.Table("scanners").
		Where("deleted_at IS NULL"). // Only update non-deleted scanners
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": now,
		})

	if result.Error != nil {
		log.Printf("Repository: Error updating all scanners: %v", result.Error)
		return 0, result.Error
	}

	log.Printf("Repository: Successfully updated %d scanners", result.RowsAffected)
	return int(result.RowsAffected), nil
}

func NewScannerRepo(db *gorm.DB) scannerPort.Repo {
	return &scannerRepo{
		db: db,
	}
}

// createSchedule creates a schedule record in the database
// The next run time and runtime should already be calculated by the service layer
func (r *scannerRepo) createSchedule(db *gorm.DB, scannerID int64, schedule *scannerDomain.Schedule) error {
	log.Printf("Repository: Creating schedule for scanner ID: %d with type: %s", scannerID, schedule.ScheduleType)

	// Create the storage schedule - business logic should already be handled by service
	storageSchedule := &types.Schedule{
		ScannerID:      scannerID,
		ScheduleType:   types.ScheduleType(schedule.ScheduleType),
		FrequencyValue: schedule.FrequencyValue,
		FrequencyUnit:  schedule.FrequencyUnit,
		Month:          schedule.Month,
		Week:           schedule.Week,
		Day:            schedule.Day,
		Hour:           schedule.Hour,
		Minute:         schedule.Minute,
		CreatedAt:      schedule.CreatedAt,
	}

	// Handle RunTime - store exactly as provided by service
	if !schedule.RunTime.IsZero() {
		storageSchedule.RunTime = &schedule.RunTime
	} else {
		storageSchedule.RunTime = nil
	}

	// Handle NextRunTime - use the value calculated by service
	if schedule.NextRunTime != nil {
		storageSchedule.NextRunTime = schedule.NextRunTime
	}

	if schedule.UpdatedAt != nil {
		storageSchedule.UpdatedAt = schedule.UpdatedAt
	}

	return db.Table("schedules").Create(storageSchedule).Error
}

func (r *scannerRepo) Create(ctx context.Context, scanner domain.ScannerDomain) (int64, error) {
	log.Printf("Repository: Creating scanner: %+v", scanner)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Convert domain model to storage model
	storageScanner := &types.Scanner{
		Name:      scanner.Name,
		ScanType:  scanner.ScanType,
		Status:    scanner.Status,
		CreatedAt: scanner.CreatedAt,
		UpdatedAt: &scanner.UpdatedAt,
	}

	if scanner.UserID != "" {
		storageScanner.UserID = &scanner.UserID
	}

	// Use a map to ensure all fields are included in the INSERT
	// This forces GORM to explicitly set status even when it's false
	scannerValues := map[string]interface{}{
		"name":       scanner.Name,
		"scan_type":  scanner.ScanType,
		"status":     scanner.Status,
		"created_at": scanner.CreatedAt,
		"updated_at": scanner.UpdatedAt,
	}

	if scanner.UserID != "" {
		scannerValues["user_id"] = scanner.UserID
	}

	// Create using the map to ensure all fields are set
	if err := db.Table("scanners").Create(scannerValues).Error; err != nil {
		log.Printf("Repository: Error creating scanner: %v", err)
		return 0, err
	}

	// Get the last inserted ID
	var lastID int64
	if err := db.Raw("SELECT LAST_INSERT_ID()").Scan(&lastID).Error; err != nil {
		log.Printf("Repository: Error getting last insert ID: %v", err)
		return 0, err
	}

	scannerID := lastID

	// Handle metadata based on scanner type
	var err error

	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		err = r.createNmapData(db, scannerID, scanner)
	case domain.ScannerTypeVCenter:
		err = r.createVcenterData(db, scannerID, scanner)
	case domain.ScannerTypeDomain:
		err = r.createDomainData(db, scannerID, scanner)
	}

	if err != nil {
		return 0, err
	}

	// Handle schedule data if it exists
	// Next run time should already be calculated by the service layer
	if scanner.Schedule != nil {
		if err := r.createSchedule(db, scannerID, scanner.Schedule); err != nil {
			return 0, err
		}
	}

	return scannerID, nil
}

// Helper method for creating Nmap related data
func (r *scannerRepo) createNmapData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	// Create Nmap metadata
	nmapMetadata := &types.NmapMetadata{
		ScannerID: scannerID,
		Type:      scanner.Type,
		Target:    scanner.Target,
	}

	if err := db.Table("nmap_metadata").Create(nmapMetadata).Error; err != nil {
		return err
	}

	metadataID := nmapMetadata.ID

	// Handle target-specific data
	switch scanner.Target {
	case "IP":
		ipScan := &types.NmapIPScan{
			NmapMetadatasID: metadataID,
			IP:              scanner.IP,
		}
		if err := db.Table("nmap_ip_scans").Create(ipScan).Error; err != nil {
			return err
		}

	case "Network":
		networkScan := &types.NmapNetworkScan{
			NmapMetadatasID: metadataID,
			IP:              scanner.IP,
			Subnet:          scanner.Subnet,
		}
		if err := db.Table("nmap_network_scans").Create(networkScan).Error; err != nil {
			return err
		}

	case "Range":
		rangeScan := &types.NmapRangeScan{
			NmapMetadatasID: metadataID,
			StartIP:         scanner.StartIP,
			EndIP:           scanner.EndIP,
		}
		if err := db.Table("nmap_range_scans").Create(rangeScan).Error; err != nil {
			return err
		}
	}

	return nil
}

// applyIDCondition applies ID-based conditions to a query based on exclude flag
func applyIDCondition(query *gorm.DB, ids []int64, exclude bool) *gorm.DB {
	if len(ids) == 0 {
		return query
	}

	if exclude {
		// Exclude specified IDs
		return query.Where("id NOT IN ?", ids)
	}
	// Include only specified IDs
	return query.Where("id IN ?", ids)
}

// applyScannerFiltersToQuery applies filter conditions to a query
func applyScannerFiltersToQuery(query *gorm.DB, filters *domain.ScannerFilter) *gorm.DB {
	if filters == nil {
		return query
	}

	if filters.Name != "" {
		query = query.Where("name LIKE ?", "%"+filters.Name+"%")
	}

	if filters.ScanType != "" {
		query = query.Where("scan_type = ?", filters.ScanType)
	}

	// Only apply status filter if explicitly provided
	if filters.Status != nil {
		query = query.Where("status = ?", *filters.Status)
	}

	return query
}

// DeleteBatch is a unified method that handles all scanner deletion scenarios
func (r *scannerRepo) DeleteBatch(ctx context.Context, params domain.DeleteParams) (int, error) {
	currentTime := time.Now()
	query := r.db.WithContext(ctx).Table("scanners")

	// Always only delete non-deleted scanners
	query = query.Where("deleted_at IS NULL")

	// Case 1: Single scanner deletion by ID
	if params.ID != nil {
		result := query.Where("id = ?", *params.ID).
			Update("deleted_at", currentTime)

		if result.Error != nil {
			return 0, result.Error
		}

		return int(result.RowsAffected), nil
	}

	// Use transaction for all other cases to ensure atomicity
	var affectedRows int64
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txQuery := tx.Table("scanners").Where("deleted_at IS NULL")

		// Apply filters if they exist
		txQuery = applyScannerFiltersToQuery(txQuery, params.Filters)

		// Apply ID conditions if IDs exist
		if len(params.IDs) > 0 {
			txQuery = applyIDCondition(txQuery, params.IDs, params.Exclude)
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

// Updated List method to handle schedule types and nullable RunTime
func (r *scannerRepo) List(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error) {
	log.Printf("Repository: Listing scanners with filter: %+v, pagination: %+v", filter, pagination)

	// Use the query package to handle filtering, sorting, and pagination
	queryBuilder := query.NewGormQueryBuilder(r.db.Table("scanners").WithContext(ctx).Where("deleted_at IS NULL"))

	// Apply filters
	if filter.Name != "" {
		queryBuilder.AddFilter("name LIKE ?", "%"+filter.Name+"%")
	}

	if filter.ScanType != "" {
		queryBuilder.AddFilter("scan_type = ?", filter.ScanType)
	}

	// Only apply status filter if it's explicitly provided
	if filter.Status != nil {
		queryBuilder.AddFilter("status = ?", *filter.Status)
		log.Printf("Repository: Applying status filter: %v", *filter.Status)
	} else {
		log.Printf("Repository: No status filter provided, fetching all scanners regardless of status")
	}

	// Get total count before applying pagination
	var totalCount int64
	countQuery := queryBuilder.BuildForCount()
	if err := countQuery.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	// Apply sorting
	if pagination.SortField != "" {
		sortOrder := "asc"
		if pagination.SortOrder == "desc" {
			sortOrder = "desc"
		}
		queryBuilder.AddSort(pagination.SortField, sortOrder)
	} else {
		// Default sort by ID ascending
		queryBuilder.AddSort("id", "asc")
	}

	// Apply pagination
	if pagination.Limit > 0 {
		offset := pagination.Page * pagination.Limit
		queryBuilder.SetPagination(pagination.Limit, offset)
	}

	// Execute the query
	var scanners []types.Scanner
	finalQuery := queryBuilder.Build()

	if err := finalQuery.Find(&scanners).Error; err != nil {
		log.Printf("Repository: Error listing scanners: %v", err)
		return nil, 0, err
	}

	// Convert to domain models and load related data
	var result []domain.ScannerDomain
	for _, s := range scanners {
		// Create domain scanner
		scanner := domain.ScannerDomain{
			ID:        s.ID,
			Name:      s.Name,
			ScanType:  s.ScanType,
			Status:    s.Status,
			CreatedAt: s.CreatedAt,
		}

		if s.UserID != nil {
			scanner.UserID = *s.UserID
		}

		if s.UpdatedAt != nil {
			scanner.UpdatedAt = *s.UpdatedAt
		}

		// Load related data for each scanner
		switch scanner.ScanType {
		case domain.ScannerTypeNmap:
			_ = r.LoadNmapData(ctx, &scanner)
		case domain.ScannerTypeVCenter:
			_ = r.LoadVcenterData(ctx, &scanner)
		case domain.ScannerTypeDomain:
			_ = r.LoadDomainData(ctx, &scanner)
		}

		// Load schedule with schedule type and handle nullable RunTime
		var schedules []types.Schedule
		if err := r.db.WithContext(ctx).Table("schedules").
			Where("scanner_id = ?", scanner.ID).
			Find(&schedules).Error; err == nil && len(schedules) > 0 {

			// Convert storage schedule type to domain schedule type
			scheduleType := domain.ScheduleTypeRecurring // default
			if schedules[0].ScheduleType != "" {
				scheduleType = domain.ScheduleType(schedules[0].ScheduleType)
			}

			// Handle nullable RunTime when converting to domain
			var domainRunTime time.Time
			if schedules[0].RunTime != nil {
				domainRunTime = *schedules[0].RunTime
			} else {
				domainRunTime = time.Time{} // Zero time if NULL
			}

			scanner.Schedule = &domain.Schedule{
				ID:             schedules[0].ID,
				ScannerID:      schedules[0].ScannerID,
				ScheduleType:   scheduleType,
				FrequencyValue: schedules[0].FrequencyValue,
				FrequencyUnit:  schedules[0].FrequencyUnit,
				RunTime:        domainRunTime, // Use the converted time
				Month:          schedules[0].Month,
				Week:           schedules[0].Week,
				Day:            schedules[0].Day,
				Hour:           schedules[0].Hour,
				Minute:         schedules[0].Minute,
				CreatedAt:      schedules[0].CreatedAt,
				UpdatedAt:      schedules[0].UpdatedAt,
			}

			// Set NextRunTime if available
			if schedules[0].NextRunTime != nil {
				scanner.Schedule.NextRunTime = schedules[0].NextRunTime
			}
		}

		result = append(result, scanner)
	}

	return result, int(totalCount), nil
}

// Helper method for updating VCenter related data
func (r *scannerRepo) updateVcenterData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing VCenter metadata
	var vcenterMetadata types.VcenterMetadata
	if err := db.Table("vcenter_metadata").Where("scanner_id = ?", scanner.ID).First(&vcenterMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new VCenter metadata if it doesn't exist
			return r.createVcenterData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update VCenter metadata
	vcenterMetadata.IP = scanner.IP
	vcenterMetadata.Port = scanner.Port
	vcenterMetadata.Username = scanner.Username
	vcenterMetadata.Password = scanner.Password

	return db.Table("vcenter_metadata").Where("id = ?", vcenterMetadata.ID).Updates(vcenterMetadata).Error
}

// Helper method for updating Domain related data
func (r *scannerRepo) updateDomainData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing Domain metadata
	var domainMetadata types.DomainMetadata
	if err := db.Table("domain_metadata").Where("scanner_id = ?", scanner.ID).First(&domainMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new Domain metadata if it doesn't exist
			return r.createDomainData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update Domain metadata
	domainMetadata.IP = scanner.IP
	domainMetadata.Port = scanner.Port
	domainMetadata.Username = scanner.Username
	domainMetadata.Password = scanner.Password
	domainMetadata.Domain = scanner.Domain
	domainMetadata.AuthenticationType = scanner.AuthenticationType
	domainMetadata.Protocol = scanner.Protocol

	return db.Table("domain_metadata").Where("id = ?", domainMetadata.ID).Updates(domainMetadata).Error
}

func (r *scannerRepo) Delete(ctx context.Context, scannerID int64) error {
	log.Printf("Repository: Deleting scanner with ID: %d", scannerID)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// First, check if the scanner exists at all (regardless of deleted status)
	var scanner types.Scanner
	err := db.Table("scanners").
		Where("id = ?", scannerID).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Repository: Scanner with ID %d does not exist", scannerID)
			return fmt.Errorf("scanner with ID %d not found", scannerID)
		}
		log.Printf("Repository: Error checking scanner existence: %v", err)
		return err
	}

	// Check if it's already deleted
	if scanner.DeletedAt != nil {
		log.Printf("Repository: Scanner with ID %d is already deleted", scannerID)
		return nil // Success - already deleted
	}

	// Soft delete by updating the deleted_at timestamp
	now := time.Now()
	result := db.Table("scanners").
		Where("id = ?", scannerID).
		Update("deleted_at", now)

	if result.Error != nil {
		log.Printf("Repository: Error deleting scanner: %v", result.Error)
		return result.Error
	}

	log.Printf("Repository: Successfully deleted scanner with ID: %d", scannerID)
	return nil
}

// Helper method for updating Nmap related data
func (r *scannerRepo) updateNmapData(db *gorm.DB, scanner domain.ScannerDomain) error {
	// Get existing Nmap metadata
	var nmapMetadata types.NmapMetadata
	if err := db.Table("nmap_metadata").Where("scanner_id = ?", scanner.ID).First(&nmapMetadata).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new Nmap metadata if it doesn't exist
			return r.createNmapData(db, scanner.ID, scanner)
		}
		return err
	}

	// Update Nmap metadata
	nmapMetadata.Type = scanner.Type
	nmapMetadata.Target = scanner.Target

	if err := db.Table("nmap_metadata").Where("id = ?", nmapMetadata.ID).Updates(nmapMetadata).Error; err != nil {
		return err
	}

	// Remove old target-specific data
	if err := db.Table("nmap_ip_scans").Where("nmap_metadatas_id = ?", nmapMetadata.ID).Delete(&types.NmapIPScan{}).Error; err != nil {
		return err
	}

	if err := db.Table("nmap_network_scans").Where("nmap_metadatas_id = ?", nmapMetadata.ID).Delete(&types.NmapNetworkScan{}).Error; err != nil {
		return err
	}

	if err := db.Table("nmap_range_scans").Where("nmap_metadatas_id = ?", nmapMetadata.ID).Delete(&types.NmapRangeScan{}).Error; err != nil {
		return err
	}

	// Create new target-specific data
	switch scanner.Target {
	case "IP":
		ipScan := &types.NmapIPScan{
			NmapMetadatasID: nmapMetadata.ID,
			IP:              scanner.IP,
		}
		if err := db.Table("nmap_ip_scans").Create(ipScan).Error; err != nil {
			return err
		}

	case "Network":
		networkScan := &types.NmapNetworkScan{
			NmapMetadatasID: nmapMetadata.ID,
			IP:              scanner.IP,
			Subnet:          scanner.Subnet,
		}
		if err := db.Table("nmap_network_scans").Create(networkScan).Error; err != nil {
			return err
		}

	case "Range":
		rangeScan := &types.NmapRangeScan{
			NmapMetadatasID: nmapMetadata.ID,
			StartIP:         scanner.StartIP,
			EndIP:           scanner.EndIP,
		}
		if err := db.Table("nmap_range_scans").Create(rangeScan).Error; err != nil {
			return err
		}
	}

	return nil
}

// Updated Update method to handle schedule types and nullable RunTime
func (r *scannerRepo) Update(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Repository: Updating scanner: %+v", scanner)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Create a map to ensure all fields, including false values, are included in the update
	updateMap := map[string]interface{}{
		"name":       scanner.Name,
		"scan_type":  scanner.ScanType,
		"status":     scanner.Status,
		"updated_at": scanner.UpdatedAt,
	}

	if scanner.UserID != "" {
		updateMap["user_id"] = scanner.UserID
	}

	// Update the scanner in the database using a map
	result := db.Table("scanners").
		Where("id = ?", scanner.ID).
		Updates(updateMap)

	// Check for any errors during the update
	if result.Error != nil {
		log.Printf("Repository: Error updating scanner: %v", result.Error)
		return result.Error
	}

	// Ensure that at least one row was affected, meaning the scanner was found and updated
	if result.RowsAffected == 0 {
		log.Printf("Repository: No rows affected when updating scanner with ID: %d", scanner.ID)
		return fmt.Errorf("scanner with ID %d not found", scanner.ID)
	}

	// Update related data based on scanner type
	var err error
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		err = r.updateNmapData(db, scanner)
	case domain.ScannerTypeVCenter:
		err = r.updateVcenterData(db, scanner)
	case domain.ScannerTypeDomain:
		err = r.updateDomainData(db, scanner)
	}

	if err != nil {
		return err
	}

	// Update schedule if it exists
	// Next run time should already be calculated by the service layer
	if scanner.Schedule != nil {
		err = r.updateSchedule(db, scanner.ID, *scanner.Schedule)
		if err != nil {
			log.Printf("Repository: Error updating schedule: %v", err)
			return err
		}
	}

	log.Printf("Repository: Successfully updated scanner with ID: %d", scanner.ID)
	return nil
}

// Helper method to update or create schedule
// Business logic should already be handled by the service layer
func (r *scannerRepo) updateSchedule(db *gorm.DB, scannerID int64, schedule domain.Schedule) error {
	log.Printf("Repository: Updating schedule for scanner ID: %d with type: %s", scannerID, schedule.ScheduleType)

	// Check if schedule exists
	var existingSchedule types.Schedule
	err := db.Table("schedules").Where("scanner_id = ?", scannerID).First(&existingSchedule).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// Prepare schedule data for update/create - use values provided by service
	scheduleMap := map[string]interface{}{
		"scanner_id":      scannerID,
		"schedule_type":   string(schedule.ScheduleType),
		"frequency_value": schedule.FrequencyValue,
		"frequency_unit":  schedule.FrequencyUnit,
		"month":           schedule.Month,
		"week":            schedule.Week,
		"day":             schedule.Day,
		"hour":            schedule.Hour,
		"minute":          schedule.Minute,
		"updated_at":      time.Now(),
	}

	// Handle RunTime - store exactly as provided by service
	if !schedule.RunTime.IsZero() {
		scheduleMap["run_time"] = schedule.RunTime.Format("2006-01-02 15:04:05")
	} else {
		scheduleMap["run_time"] = nil // Set to NULL
	}

	// Handle NextRunTime - use the value calculated by service
	if schedule.NextRunTime != nil {
		scheduleMap["next_run_time"] = schedule.NextRunTime.Format("2006-01-02 15:04:05")
	} else {
		scheduleMap["next_run_time"] = nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Create new schedule
		scheduleMap["created_at"] = time.Now()
		if err := db.Table("schedules").Create(scheduleMap).Error; err != nil {
			return err
		}
		log.Printf("Repository: Created new schedule for scanner ID: %d", scannerID)
	} else {
		// Update existing schedule
		if err := db.Table("schedules").Where("scanner_id = ?", scannerID).
			Updates(scheduleMap).Error; err != nil {
			return err
		}
		log.Printf("Repository: Updated existing schedule for scanner ID: %d", scannerID)
	}

	return nil
}

// Helper method for creating VCenter related data
func (r *scannerRepo) createVcenterData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	vcenterMetadata := &types.VcenterMetadata{
		ScannerID: scannerID,
		IP:        scanner.IP,
		Port:      scanner.Port,
		Username:  scanner.Username,
		Password:  scanner.Password,
	}

	return db.Table("vcenter_metadata").Create(vcenterMetadata).Error
}

// Helper method for creating Domain related data
func (r *scannerRepo) createDomainData(db *gorm.DB, scannerID int64, scanner domain.ScannerDomain) error {
	domainMetadata := &types.DomainMetadata{
		ScannerID:          scannerID,
		IP:                 scanner.IP,
		Port:               scanner.Port,
		Username:           scanner.Username,
		Password:           scanner.Password,
		Domain:             scanner.Domain,
		AuthenticationType: scanner.AuthenticationType,
		Protocol:           scanner.Protocol,
	}

	return db.Table("domain_metadata").Create(domainMetadata).Error
}

func (r *scannerRepo) GetByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error) {
	log.Printf("Repository: Getting scanner with ID: %d", scannerID)

	var scanner types.Scanner
	err := r.db.Table("scanners").WithContext(ctx).
		Where("id = ?", scannerID).
		First(&scanner).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Repository: Scanner not found for ID: %d", scannerID)
			return nil, nil
		}
		log.Printf("Repository: Error querying scanner: %v", err)
		return nil, err
	}

	// Convert to domain model
	domainScanner := &domain.ScannerDomain{
		ID:        scanner.ID,
		Name:      scanner.Name,
		ScanType:  scanner.ScanType,
		Status:    scanner.Status,
		CreatedAt: scanner.CreatedAt,
	}

	if scanner.UserID != nil {
		domainScanner.UserID = *scanner.UserID
	}

	if scanner.UpdatedAt != nil {
		domainScanner.UpdatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		domainScanner.DeletedAt = *scanner.DeletedAt
	}

	// Load all related data based on scanner type
	switch domainScanner.ScanType {
	case domain.ScannerTypeNmap:
		if err := r.LoadNmapData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeVCenter:
		if err := r.LoadVcenterData(ctx, domainScanner); err != nil {
			return nil, err
		}
	case domain.ScannerTypeDomain:
		if err := r.LoadDomainData(ctx, domainScanner); err != nil {
			return nil, err
		}
	}

	// Load schedule data with schedule type and handle nullable RunTime
	var schedules []types.Schedule
	if err := r.db.WithContext(ctx).Table("schedules").
		Where("scanner_id = ?", scannerID).
		Find(&schedules).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if len(schedules) > 0 {
		// Convert storage schedule type to domain schedule type
		scheduleType := domain.ScheduleTypeRecurring // default
		if schedules[0].ScheduleType != "" {
			scheduleType = domain.ScheduleType(schedules[0].ScheduleType)
		}

		// Handle nullable RunTime when converting to domain
		var domainRunTime time.Time
		if schedules[0].RunTime != nil {
			domainRunTime = *schedules[0].RunTime
		} else {
			domainRunTime = time.Time{} // Zero time if NULL
		}

		domainScanner.Schedule = &domain.Schedule{
			ID:             schedules[0].ID,
			ScannerID:      schedules[0].ScannerID,
			ScheduleType:   scheduleType,
			FrequencyValue: schedules[0].FrequencyValue,
			FrequencyUnit:  schedules[0].FrequencyUnit,
			RunTime:        domainRunTime, // Use the converted time
			Month:          schedules[0].Month,
			Week:           schedules[0].Week,
			Day:            schedules[0].Day,
			Hour:           schedules[0].Hour,
			Minute:         schedules[0].Minute,
			CreatedAt:      schedules[0].CreatedAt,
			UpdatedAt:      schedules[0].UpdatedAt,
		}

		// Set NextRunTime if available
		if schedules[0].NextRunTime != nil {
			domainScanner.Schedule.NextRunTime = schedules[0].NextRunTime
		}
	}

	return domainScanner, nil
}

// Helper method to load Nmap related data
func (r *scannerRepo) LoadNmapData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var nmapMetadata types.NmapMetadata
	if err := r.db.WithContext(ctx).Table("nmap_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&nmapMetadata).Error; err != nil {
		return err
	}

	scanner.Type = nmapMetadata.Type
	scanner.Target = nmapMetadata.Target

	// Load target-specific data
	switch nmapMetadata.Target {
	case "IP":
		var ipScan types.NmapIPScan
		if err := r.db.WithContext(ctx).Table("nmap_ip_scans").
			Where("nmap_metadatas_id = ?", nmapMetadata.ID).
			First(&ipScan).Error; err != nil {
			return err
		}
		scanner.IP = ipScan.IP

	case "Network":
		var networkScan types.NmapNetworkScan
		if err := r.db.WithContext(ctx).Table("nmap_network_scans").
			Where("nmap_metadatas_id = ?", nmapMetadata.ID).
			First(&networkScan).Error; err != nil {
			return err
		}
		scanner.IP = networkScan.IP
		scanner.Subnet = networkScan.Subnet

	case "Range":
		var rangeScan types.NmapRangeScan
		if err := r.db.WithContext(ctx).Table("nmap_range_scans").
			Where("nmap_metadatas_id = ?", nmapMetadata.ID).
			First(&rangeScan).Error; err != nil {
			return err
		}
		scanner.StartIP = rangeScan.StartIP
		scanner.EndIP = rangeScan.EndIP
	}

	return nil
}

// Helper method to load VCenter related data
func (r *scannerRepo) LoadVcenterData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var vcenterMetadata types.VcenterMetadata
	if err := r.db.WithContext(ctx).Table("vcenter_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&vcenterMetadata).Error; err != nil {
		return err
	}

	scanner.IP = vcenterMetadata.IP
	scanner.Port = vcenterMetadata.Port
	scanner.Username = vcenterMetadata.Username
	scanner.Password = vcenterMetadata.Password

	return nil
}

// Helper method to load Domain related data
func (r *scannerRepo) LoadDomainData(ctx context.Context, scanner *domain.ScannerDomain) error {
	var domainMetadata types.DomainMetadata
	if err := r.db.WithContext(ctx).Table("domain_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&domainMetadata).Error; err != nil {
		return err
	}

	scanner.IP = domainMetadata.IP
	scanner.Port = domainMetadata.Port
	scanner.Username = domainMetadata.Username
	scanner.Password = domainMetadata.Password
	scanner.Domain = domainMetadata.Domain
	scanner.AuthenticationType = domainMetadata.AuthenticationType
	scanner.Protocol = domainMetadata.Protocol

	return nil
}

// UpdateScannerStatus implements a unified approach to update scanner status based on various criteria
func (r *scannerRepo) UpdateScannerStatus(ctx context.Context, params domain.StatusUpdateParams) (int, error) {
	log.Printf("Repository: Updating scanner status with params: IDs=%v, Filter=%+v, Status=%v, Exclude=%v, UpdateAll=%v",
		params.IDs, params.Filter, params.Status, params.Exclude, params.UpdateAll)

	if len(params.IDs) == 0 && !params.UpdateAll && params.Filter.Name == "" &&
		params.Filter.ScanType == "" && params.Filter.Status == nil {
		log.Printf("Repository: No update criteria provided")
		return 0, nil
	}

	// Get the DB from context or use repo default
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Start building base query
	query := db.Table("scanners").Where("deleted_at IS NULL")

	// If filter provided, apply it
	if params.Filter.Name != "" {
		query = query.Where("name LIKE ?", "%"+params.Filter.Name+"%")
	}
	if params.Filter.ScanType != "" {
		query = query.Where("UPPER(scan_type) = UPPER(?)", params.Filter.ScanType)
	}
	if params.Filter.Status != nil {
		query = query.Where("status = ?", *params.Filter.Status)
	}

	// Apply exclusion logic
	if params.Exclude {
		var excludedIDs []int64

		if params.UpdateAll || params.Filter.Name != "" || params.Filter.ScanType != "" || params.Filter.Status != nil {
			if err := query.Pluck("id", &excludedIDs).Error; err != nil {
				log.Printf("Repository: Error fetching IDs for exclusion: %v", err)
				return 0, err
			}
		} else {
			excludedIDs = params.IDs
		}

		query = db.Table("scanners").Where("deleted_at IS NULL")

		if len(excludedIDs) > 0 {
			query = query.Where("id NOT IN ?", excludedIDs)
		}
	} else {
		// Not excluding, limit by IDs if provided
		if len(params.IDs) > 0 {
			query = query.Where("id IN ?", params.IDs)
		}
	}

	// Apply status update
	now := time.Now()
	result := query.Updates(map[string]interface{}{
		"status":     params.Status,
		"updated_at": now,
	})

	if result.Error != nil {
		log.Printf("Repository: Error updating scanners: %v", result.Error)
		return 0, result.Error
	}

	log.Printf("Repository: Successfully updated %d scanners", result.RowsAffected)
	return int(result.RowsAffected), nil
}