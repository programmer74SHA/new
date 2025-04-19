package storage

import (
	"context"
	"errors"
	"log"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	appCtx "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
	"gorm.io/gorm"
)

type schedulerRepo struct {
	db *gorm.DB
}

// NewSchedulerRepo creates a new scheduler repository
func NewSchedulerRepo(db *gorm.DB) port.Repo {
	return &schedulerRepo{
		db: db,
	}
}

// GetDueSchedules retrieves all scheduled scans that are due to run
func (r *schedulerRepo) GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error) {
	log.Printf("Scheduler Repository: Getting due schedules")

	var scheduledScans []domain.ScheduledScan
	now := time.Now()

	// First, get all active scanners with schedules that are due to run
	// We join scanners and schedules tables to get only active scanners with schedules
	// and filter by next_run_time <= now AND next_run_time IS NOT NULL
	rows, err := r.db.WithContext(ctx).Raw(`
		SELECT 
			s.id, s.name, s.scan_type, s.status, s.created_at, s.updated_at, s.user_id, s.deleted_at,
			sch.id, sch.scanner_id, sch.frequency_value, sch.frequency_unit, 
			sch.month, sch.week, sch.day, sch.hour, sch.minute, sch.next_run_time
		FROM 
			scanners s
		INNER JOIN 
			schedules sch ON s.id = sch.scanner_id
		WHERE 
			s.status = true 
			AND s.deleted_at IS NULL
			AND sch.next_run_time IS NOT NULL 
			AND sch.next_run_time <= ?
	`, now).Rows()

	if err != nil {
		log.Printf("Scheduler Repository: Error getting due schedules: %v", err)
		return nil, err
	}
	defer rows.Close()

	// Process the results
	for rows.Next() {
		var scanner types.Scanner
		var schedule types.Schedule
		var nextRunTime *time.Time

		// Scan values into our structs
		err := rows.Scan(
			&scanner.ID, &scanner.Name, &scanner.ScanType, &scanner.Status,
			&scanner.CreatedAt, &scanner.UpdatedAt, &scanner.UserID, &scanner.DeletedAt,
			&schedule.ID, &schedule.ScannerID, &schedule.FrequencyValue, &schedule.FrequencyUnit,
			&schedule.Month, &schedule.Week, &schedule.Day, &schedule.Hour, &schedule.Minute,
			&nextRunTime,
		)

		if err != nil {
			log.Printf("Scheduler Repository: Error scanning row: %v", err)
			continue
		}

		schedule.NextRunTime = nextRunTime

		// Convert scanner to domain model
		scannerDomainModel := &scannerDomain.ScannerDomain{
			ID:        scanner.ID,
			Name:      scanner.Name,
			ScanType:  scanner.ScanType,
			Status:    scanner.Status,
			CreatedAt: scanner.CreatedAt,
		}

		if scanner.UserID != nil {
			scannerDomainModel.UserID = *scanner.UserID
		}

		if scanner.UpdatedAt != nil {
			scannerDomainModel.UpdatedAt = *scanner.UpdatedAt
		}

		// Now, fetch the metadata based on scanner type
		switch scannerDomainModel.ScanType {
		case scannerDomain.ScannerTypeNmap:
			// Get Nmap metadata
			if err := r.loadNmapData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading Nmap data for scanner %d: %v", scanner.ID, err)
				continue
			}
		case scannerDomain.ScannerTypeVCenter:
			if err := r.loadVcenterData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading VCenter data for scanner %d: %v", scanner.ID, err)
				continue
			}
		case scannerDomain.ScannerTypeDomain:
			if err := r.loadDomainData(ctx, scannerDomainModel); err != nil {
				log.Printf("Error loading Domain data for scanner %d: %v", scanner.ID, err)
				continue
			}
		}

		// Convert schedule to domain model
		scheduleDomainModel := scannerDomain.Schedule{
			ID:             schedule.ID,
			ScannerID:      schedule.ScannerID,
			FrequencyValue: schedule.FrequencyValue,
			FrequencyUnit:  schedule.FrequencyUnit,
			Month:          schedule.Month,
			Week:           schedule.Week,
			Day:            schedule.Day,
			Hour:           schedule.Hour,
			Minute:         schedule.Minute,
		}

		// Set next run time from the database
		nextRun := now
		if schedule.NextRunTime != nil {
			nextRun = *schedule.NextRunTime
		}

		// Create scheduled scan entry
		scheduledScan := domain.ScheduledScan{
			Scanner:     *scannerDomainModel,
			Schedule:    scheduleDomainModel,
			NextRunTime: nextRun,
		}

		scheduledScans = append(scheduledScans, scheduledScan)
	}

	log.Printf("Scheduler Repository: Found %d due schedules", len(scheduledScans))
	return scheduledScans, nil
}

func (r *schedulerRepo) loadNmapData(ctx context.Context, scanner *scannerDomain.ScannerDomain) error {
	var nmapMeta types.NmapMetadata
	if err := r.db.WithContext(ctx).
		Table("nmap_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&nmapMeta).Error; err != nil {
		return err
	}

	// Add metadata to scanner domain model
	scanner.Type = nmapMeta.Type
	scanner.Target = nmapMeta.Target

	// Get target-specific data
	switch nmapMeta.Target {
	case "IP":
		var ipScan types.NmapIPScan
		if err := r.db.WithContext(ctx).
			Table("nmap_ip_scans").
			Where("nmap_metadatas_id = ?", nmapMeta.ID).
			First(&ipScan).Error; err == nil {
			scanner.IP = ipScan.IP
		}
	case "Network":
		var networkScan types.NmapNetworkScan
		if err := r.db.WithContext(ctx).
			Table("nmap_network_scans").
			Where("nmap_metadatas_id = ?", nmapMeta.ID).
			First(&networkScan).Error; err == nil {
			scanner.IP = networkScan.IP
			scanner.Subnet = networkScan.Subnet
		}
	case "Range":
		var rangeScan types.NmapRangeScan
		if err := r.db.WithContext(ctx).
			Table("nmap_range_scans").
			Where("nmap_metadatas_id = ?", nmapMeta.ID).
			First(&rangeScan).Error; err == nil {
			scanner.StartIP = rangeScan.StartIP
			scanner.EndIP = rangeScan.EndIP
		}
	}

	return nil
}

// Helper method to load VCenter related data
func (r *schedulerRepo) loadVcenterData(ctx context.Context, scanner *scannerDomain.ScannerDomain) error {
	var vcenterMeta types.VcenterMetadata
	if err := r.db.WithContext(ctx).
		Table("vcenter_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&vcenterMeta).Error; err != nil {
		return err
	}

	scanner.IP = vcenterMeta.IP
	scanner.Port = vcenterMeta.Port
	scanner.Username = vcenterMeta.Username
	scanner.Password = vcenterMeta.Password

	return nil
}

// Helper method to load Domain related data
func (r *schedulerRepo) loadDomainData(ctx context.Context, scanner *scannerDomain.ScannerDomain) error {
	var domainMeta types.DomainMetadata
	if err := r.db.WithContext(ctx).
		Table("domain_metadata").
		Where("scanner_id = ?", scanner.ID).
		First(&domainMeta).Error; err != nil {
		return err
	}

	scanner.IP = domainMeta.IP
	scanner.Port = domainMeta.Port
	scanner.Username = domainMeta.Username
	scanner.Password = domainMeta.Password
	scanner.Domain = domainMeta.Domain
	scanner.AuthenticationType = domainMeta.AuthenticationType

	return nil
}

// CreateScanJob creates a new scan job record
func (r *schedulerRepo) CreateScanJob(ctx context.Context, job domain.ScanJob) (int64, error) {
	log.Printf("Scheduler Repository: Creating scan job for scanner ID: %d", job.ScannerID)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Convert job status to database enum value
	status := string(job.Status)

	// Create scan job record
	scanJob := types.ScanJob{
		Name:      job.Name,
		Type:      job.Type,
		Status:    status,
		StartTime: job.StartTime,
		Progress:  &job.Progress,
		ScannerID: job.ScannerID,
	}

	// Insert the record
	if err := db.Table("scan_jobs").Create(&scanJob).Error; err != nil {
		log.Printf("Scheduler Repository: Error creating scan job: %v", err)
		return 0, err
	}

	log.Printf("Scheduler Repository: Created scan job with ID: %d", scanJob.ID)
	return scanJob.ID, nil
}

// UpdateScanJobStatus updates the status of an existing scan job
func (r *schedulerRepo) UpdateScanJobStatus(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int) error {
	log.Printf("Scheduler Repository: Updating scan job ID: %d to status: %s with progress: %d", jobID, status, progress)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Map domain status to database enum value
	var statusStr string
	switch status {
	case domain.ScheduleStatusComplete:
		statusStr = "Completed"
	case domain.ScheduleStatusFailed:
		statusStr = "Failed"
	case domain.ScheduleStatusPending:
		statusStr = "Pending"
	case domain.ScheduleStatusRunning:
		statusStr = "Running"
	case domain.ScheduleStatusCancelled:
		statusStr = "Cancelled" // Map the new Cancelled status
	default:
		statusStr = "Error"
	}

	// Update the record
	result := db.Table("scan_jobs").
		Where("id = ?", jobID).
		Updates(map[string]interface{}{
			"status":   statusStr,
			"progress": progress,
		})

	if result.Error != nil {
		log.Printf("Scheduler Repository: Error updating scan job: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Scheduler Repository: No rows affected when updating scan job ID: %d", jobID)
		return errors.New("scan job not found")
	}

	log.Printf("Scheduler Repository: Successfully updated scan job ID: %d", jobID)
	return nil
}

// CompleteScanJob marks a scan job as complete
func (r *schedulerRepo) CompleteScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus) error {
	log.Printf("Scheduler Repository: Completing scan job ID: %d with status: %s", jobID, status)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Map domain status to database enum value
	var statusStr string
	switch status {
	case domain.ScheduleStatusComplete:
		statusStr = "Completed"
	case domain.ScheduleStatusFailed:
		statusStr = "Failed"
	case domain.ScheduleStatusPending:
		statusStr = "Pending"
	case domain.ScheduleStatusRunning:
		statusStr = "Running"
	case domain.ScheduleStatusCancelled:
		statusStr = "Cancelled" // Map the new Cancelled status
	default:
		statusStr = "Error"
	}

	now := time.Now()

	// Update the record
	result := db.Table("scan_jobs").
		Where("id = ?", jobID).
		Updates(map[string]interface{}{
			"status":   statusStr,
			"end_time": now,
			"progress": 100, // Set progress to 100% when completing
		})

	if result.Error != nil {
		log.Printf("Scheduler Repository: Error completing scan job: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Scheduler Repository: No rows affected when completing scan job ID: %d", jobID)
		return errors.New("scan job not found")
	}

	log.Printf("Scheduler Repository: Successfully completed scan job ID: %d", jobID)
	return nil
}

// GetScannerWithSchedule retrieves a scanner with its associated schedule
func (r *schedulerRepo) GetScannerWithSchedule(ctx context.Context, scannerID int64) (*domain.ScheduledScan, error) {
	log.Printf("Scheduler Repository: Getting scanner with ID: %d", scannerID)

	// Get the scanner
	var scanner types.Scanner
	if err := r.db.WithContext(ctx).
		Table("scanners").
		Where("id = ?", scannerID).
		Where("deleted_at IS NULL").
		First(&scanner).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Scheduler Repository: Scanner not found with ID: %d", scannerID)
			return nil, nil
		}
		log.Printf("Scheduler Repository: Error getting scanner: %v", err)
		return nil, err
	}

	// Get the schedule
	var schedule types.Schedule
	if err := r.db.WithContext(ctx).
		Table("schedules").
		Where("scanner_id = ?", scannerID).
		First(&schedule).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("Scheduler Repository: Schedule not found for scanner ID: %d", scannerID)
			return nil, nil
		}
		log.Printf("Scheduler Repository: Error getting schedule: %v", err)
		return nil, err
	}

	// Convert to domain models
	scannerDomainModel := &scannerDomain.ScannerDomain{
		ID:        scanner.ID,
		Name:      scanner.Name,
		ScanType:  scanner.ScanType,
		Status:    scanner.Status,
		CreatedAt: scanner.CreatedAt,
	}

	if scanner.UserID != nil {
		scannerDomainModel.UserID = *scanner.UserID
	}

	if scanner.UpdatedAt != nil {
		scannerDomainModel.UpdatedAt = *scanner.UpdatedAt
	}

	scheduleDomainModel := scannerDomain.Schedule{
		ID:             schedule.ID,
		ScannerID:      schedule.ScannerID,
		FrequencyValue: schedule.FrequencyValue,
		FrequencyUnit:  schedule.FrequencyUnit,
		Month:          schedule.Month,
		Week:           schedule.Week,
		Day:            schedule.Day,
		Hour:           schedule.Hour,
		Minute:         schedule.Minute,
	}

	// Get next run time if available
	var nextRunTime time.Time
	if schedule.NextRunTime != nil {
		nextRunTime = *schedule.NextRunTime
	} else {
		// Calculate next run time if not available
		nextRunTime = domain.CalculateNextRunTime(scheduleDomainModel, time.Now())
	}

	// Create scheduled scan
	scheduledScan := &domain.ScheduledScan{
		Scanner:     *scannerDomainModel,
		Schedule:    scheduleDomainModel,
		NextRunTime: nextRunTime,
	}

	return scheduledScan, nil
}

// GetActiveScanners retrieves all active scanners with their schedules
func (r *schedulerRepo) GetActiveScanners(ctx context.Context) ([]domain.ScheduledScan, error) {
	log.Printf("Scheduler Repository: Getting all active scanners")

	var scheduledScans []domain.ScheduledScan

	// Get all active scanners
	var scanners []types.Scanner
	if err := r.db.WithContext(ctx).
		Table("scanners").
		Where("status = ?", true).
		Where("deleted_at IS NULL").
		Find(&scanners).Error; err != nil {
		log.Printf("Scheduler Repository: Error getting active scanners: %v", err)
		return nil, err
	}

	log.Printf("Scheduler Repository: Found %d active scanners", len(scanners))

	// For each scanner, get its schedule
	for _, scanner := range scanners {
		var schedules []types.Schedule
		if err := r.db.WithContext(ctx).
			Table("schedules").
			Where("scanner_id = ?", scanner.ID).
			Find(&schedules).Error; err != nil {
			log.Printf("Scheduler Repository: Error getting schedules for scanner %d: %v", scanner.ID, err)
			continue
		}

		// Skip scanners without schedules
		if len(schedules) == 0 {
			continue
		}

		// Convert scanner to domain model
		scannerDomainModel := &scannerDomain.ScannerDomain{
			ID:        scanner.ID,
			Name:      scanner.Name,
			ScanType:  scanner.ScanType,
			Status:    scanner.Status,
			CreatedAt: scanner.CreatedAt,
		}

		if scanner.UserID != nil {
			scannerDomainModel.UserID = *scanner.UserID
		}

		if scanner.UpdatedAt != nil {
			scannerDomainModel.UpdatedAt = *scanner.UpdatedAt
		}

		for _, schedule := range schedules {
			// Convert schedule to domain model
			scheduleDomainModel := scannerDomain.Schedule{
				ID:             schedule.ID,
				ScannerID:      schedule.ScannerID,
				FrequencyValue: schedule.FrequencyValue,
				FrequencyUnit:  schedule.FrequencyUnit,
				Month:          schedule.Month,
				Week:           schedule.Week,
				Day:            schedule.Day,
				Hour:           schedule.Hour,
				Minute:         schedule.Minute,
			}

			// Get the next run time
			var nextRunTime time.Time
			if schedule.NextRunTime != nil {
				nextRunTime = *schedule.NextRunTime
			} else {
				// Calculate next run time if not available
				nextRunTime = domain.CalculateNextRunTime(scheduleDomainModel, time.Now())
			}

			// Create scheduled scan entry
			scheduledScan := domain.ScheduledScan{
				Scanner:     *scannerDomainModel,
				Schedule:    scheduleDomainModel,
				NextRunTime: nextRunTime,
			}

			scheduledScans = append(scheduledScans, scheduledScan)
		}
	}

	log.Printf("Scheduler Repository: Returning %d scheduled scans", len(scheduledScans))
	return scheduledScans, nil
}

// UpdateScheduleNextRun updates the next run time for a schedule
func (r *schedulerRepo) UpdateScheduleNextRun(ctx context.Context, scheduleID int64, nextRunTimeStr string) error {
	log.Printf("Scheduler Repository: Updating next run time for schedule ID: %d to %s", scheduleID, nextRunTimeStr)

	// Get the DB from context or use the repo's DB
	db := appCtx.GetDB(ctx)
	if db == nil {
		db = r.db
	}

	// Parse the next run time with RFC3339 format which preserves timezone information
	nextRun, err := time.Parse(time.RFC3339, nextRunTimeStr)
	if err != nil {
		log.Printf("Scheduler Repository: Error parsing next run time: %v", err)
		return err
	}

	// Debug log the parsed time
	log.Printf("Scheduler Repository: Parsed next run time: %v", nextRun)

	// Explicitly keep the time in local database time to avoid timezone issues
	// This assumes MySQL is configured to use the same timezone as the application
	// If using a different timezone for the database, adjust accordingly
	formattedTime := nextRun.Format("2006-01-02 15:04:05")
	log.Printf("Scheduler Repository: Formatted time for database: %s", formattedTime)

	// Update the schedule using raw SQL to ensure proper time formatting
	result := db.Exec(
		"UPDATE schedules SET next_run_time = ?, updated_at = ? WHERE id = ?",
		formattedTime,
		time.Now().Format("2006-01-02 15:04:05"),
		scheduleID,
	)

	if result.Error != nil {
		log.Printf("Scheduler Repository: Error updating next run time: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected == 0 {
		log.Printf("Scheduler Repository: No rows affected when updating schedule ID: %d", scheduleID)
		return errors.New("schedule not found")
	}

	log.Printf("Scheduler Repository: Successfully updated next run time for schedule ID: %d", scheduleID)
	return nil
}
