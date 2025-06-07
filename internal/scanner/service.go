package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/encrypt"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	scheduler "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler"
)

var (
	ErrScannerOnCreate     = errors.New("error on creating new scanner")
	ErrScannerOnUpdate     = errors.New("error on updating scanner")
	ErrScannerOnDelete     = errors.New("error on deleting scanner")
	ErrScannerNotFound     = errors.New("scanner not found")
	ErrInvalidScannerInput = errors.New("invalid scanner input")
	ErrScheduleRequired    = errors.New("schedule is required")
)

type scannerService struct {
	repo scannerPort.Repo
}

func NewScannerService(repo scannerPort.Repo) scannerPort.Service {
	return &scannerService{
		repo: repo,
	}
}

// calculateNextRunTime calculates the next run time for a schedule based on its type
func (s *scannerService) calculateNextRunTime(schedule domain.Schedule) (nextRunTime time.Time, runTime *time.Time) {
	now := time.Now()

	switch schedule.ScheduleType {
	case domain.ScheduleTypeImmediately:
		// For immediate scans, set next run time to now so they get picked up right away
		nextRunTime = now
		// For immediate schedules, run_time can be NULL since it doesn't have meaning
		runTime = nil
		log.Printf("Service: Immediate schedule - setting next run time to now: %v", nextRunTime)

	case domain.ScheduleTypeRunOnce:
		// For run-once schedules, calculate based on provided time components
		nextRunTime = scheduler.CalculateNextRunTime(schedule, now)
		// For run-once, use the provided RunTime if it's not zero
		if !schedule.RunTime.IsZero() {
			runTime = &schedule.RunTime
		} else {
			runTime = &nextRunTime
		}
		log.Printf("Service: Run-once schedule - calculated next run time: %v", nextRunTime)

	case domain.ScheduleTypeRecurring:
		// For recurring schedules, calculate next occurrence
		nextRunTime = scheduler.CalculateNextRunTime(schedule, now)
		// For recurring, use the provided RunTime if it's not zero, otherwise set to NULL
		if !schedule.RunTime.IsZero() {
			runTime = &schedule.RunTime
		} else {
			runTime = nil // Can be NULL for recurring schedules that don't specify a specific run time
		}
		log.Printf("Service: Recurring schedule - calculated next run time: %v", nextRunTime)

	default:
		// Default to recurring behavior
		log.Printf("Service: Unknown schedule type %s, defaulting to recurring", schedule.ScheduleType)
		schedule.ScheduleType = domain.ScheduleTypeRecurring
		nextRunTime = scheduler.CalculateNextRunTime(schedule, now)
		runTime = nil
	}

	return nextRunTime, runTime
}

// prepareScheduleForPersistence prepares a schedule for database persistence with calculated next run time
func (s *scannerService) prepareScheduleForPersistence(schedule *domain.Schedule, scannerID int64) {
	schedule.ScannerID = scannerID

	// Calculate next run time and runtime
	nextRunTime, runTime := s.calculateNextRunTime(*schedule)

	// Store the calculated values in the schedule for the repository to use
	schedule.NextRunTime = &nextRunTime
	if runTime != nil {
		schedule.RunTime = *runTime
	} else {
		schedule.RunTime = time.Time{} // Zero time will be handled as NULL in repository
	}
}

// validateScanner ensures scanner has all required fields based on type and schedule
func (s *scannerService) validateScanner(scanner *domain.ScannerDomain) error {
	// Basic validation for required fields
	if scanner.Name == "" {
		return fmt.Errorf("scanner name is required")
	}

	if scanner.ScanType == "" {
		return fmt.Errorf("scanner type is required")
	}

	// Schedule is required
	if scanner.Schedule == nil {
		return ErrScheduleRequired
	}

	// Set default schedule type if not provided
	if scanner.Schedule.ScheduleType == "" {
		log.Printf("Service: No schedule type provided, defaulting to RECURRING")
		scanner.Schedule.ScheduleType = domain.ScheduleTypeRecurring
	}

	// Validate scanner configuration based on type
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		if err := s.validateNmapScanner(*scanner); err != nil {
			return err
		}

	case domain.ScannerTypeVCenter:
		if err := s.validateVCenterScanner(*scanner); err != nil {
			return err
		}

	case domain.ScannerTypeDomain:
		if err := s.validateDomainScanner(*scanner); err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid scanner type: %s", scanner.ScanType)
	}

	// Validate schedule configuration
	if err := s.validateSchedule(*scanner.Schedule); err != nil {
		return err
	}

	return nil
}

// validateNmapScanner validates NMAP-specific configuration
func (s *scannerService) validateNmapScanner(scanner domain.ScannerDomain) error {
	if scanner.Target == "" || scanner.Type == "" {
		return fmt.Errorf("NMAP scanner requires target and type")
	}

	switch scanner.Target {
	case "IP":
		if scanner.IP == "" {
			return fmt.Errorf("NMAP IP scan requires an IP address")
		}
	case "Network":
		if scanner.IP == "" || scanner.Subnet == 0 {
			return fmt.Errorf("NMAP Network scan requires IP and subnet")
		}
	case "Range":
		if scanner.StartIP == "" || scanner.EndIP == "" {
			return fmt.Errorf("NMAP Range scan requires start and end IPs")
		}
	default:
		return fmt.Errorf("invalid NMAP target type: %s", scanner.Target)
	}

	return nil
}

// validateVCenterScanner validates VCenter-specific configuration
func (s *scannerService) validateVCenterScanner(scanner domain.ScannerDomain) error {
	if scanner.IP == "" {
		return fmt.Errorf("VCenter scanner requires IP address")
	}
	if scanner.Port == "" {
		return fmt.Errorf("VCenter scanner requires port")
	}
	if scanner.Username == "" {
		return fmt.Errorf("VCenter scanner requires username")
	}
	if scanner.Password == "" {
		return fmt.Errorf("VCenter scanner requires password")
	}
	return nil
}

// validateDomainScanner validates Domain-specific configuration
func (s *scannerService) validateDomainScanner(scanner domain.ScannerDomain) error {
	if scanner.IP == "" {
		return fmt.Errorf("Domain scanner requires IP address")
	}
	if scanner.Port == "" {
		return fmt.Errorf("Domain scanner requires port")
	}
	if scanner.Username == "" {
		return fmt.Errorf("Domain scanner requires username")
	}
	if scanner.Password == "" {
		return fmt.Errorf("Domain scanner requires password")
	}
	if scanner.Domain == "" {
		return fmt.Errorf("Domain scanner requires domain")
	}
	if scanner.AuthenticationType == "" {
		return fmt.Errorf("Domain scanner requires authentication type")
	}
	return nil
}

// validateSchedule validates schedule configuration based on schedule type
func (s *scannerService) validateSchedule(schedule domain.Schedule) error {
	// Validate schedule type
	switch schedule.ScheduleType {
	case domain.ScheduleTypeRecurring:
		// Recurring schedules require frequency settings
		if schedule.FrequencyValue <= 0 || schedule.FrequencyUnit == "" {
			return fmt.Errorf("recurring schedule requires frequency value and unit")
		}

		// Validate frequency unit
		validUnits := []string{"minute", "hour", "day", "week", "month"}
		isValidUnit := false
		for _, unit := range validUnits {
			if schedule.FrequencyUnit == unit {
				isValidUnit = true
				break
			}
		}
		if !isValidUnit {
			return fmt.Errorf("invalid frequency unit: %s. Valid units are: minute, hour, day, week, month", schedule.FrequencyUnit)
		}

	case domain.ScheduleTypeRunOnce:
		// Run-once schedules should have either a RunTime or specific time components
		hasRunTime := !schedule.RunTime.IsZero()
		hasTimeComponents := schedule.Hour >= 0 && schedule.Minute >= 0

		if !hasRunTime && !hasTimeComponents {
			return fmt.Errorf("run-once schedule requires either run_time or specific hour/minute")
		}

	case domain.ScheduleTypeImmediately:
		// Immediate schedules don't require any additional validation
		log.Printf("Immediate schedule validated - no additional requirements")

	default:
		return fmt.Errorf("invalid schedule type: %s. Valid types are: RECURRING, RUN_ONCE, IMMEDIATELY", schedule.ScheduleType)
	}

	// Additional time validation for schedules that specify time components
	if schedule.Hour >= 0 && (schedule.Hour < 0 || schedule.Hour > 23) {
		return fmt.Errorf("invalid hour value: %d. Valid range is 0-23", schedule.Hour)
	}

	if schedule.Minute >= 0 && (schedule.Minute < 0 || schedule.Minute > 59) {
		return fmt.Errorf("invalid minute value: %d. Valid range is 0-59", schedule.Minute)
	}

	if schedule.Day > 0 && (schedule.Day < 1 || schedule.Day > 7) {
		return fmt.Errorf("invalid day value: %d. Valid range is 1-7", schedule.Day)
	}

	if schedule.Week > 0 && (schedule.Week < 1 || schedule.Week > 52) {
		return fmt.Errorf("invalid week value: %d. Valid range is 1-52", schedule.Week)
	}

	if schedule.Month > 0 && (schedule.Month < 1 || schedule.Month > 12) {
		return fmt.Errorf("invalid month value: %d. Valid range is 1-12", schedule.Month)
	}

	return nil
}

func (s *scannerService) CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (int64, error) {
	log.Printf("Service: Creating scanner: %+v", scanner)

	// Validate scanner (includes name, type, schedule checks)
	if err := s.validateScanner(&scanner); err != nil {
		log.Printf("Service: Scanner validation failed: %v", err)
		if errors.Is(err, ErrScheduleRequired) {
			return 0, ErrScheduleRequired
		}
		return 0, ErrInvalidScannerInput
	}

	// Set timestamps
	scanner.CreatedAt = time.Now()
	scanner.UpdatedAt = time.Now()

	// Encrypt passwords for VCenter and Domain scanners
	if scanner.ScanType == domain.ScannerTypeVCenter || scanner.ScanType == domain.ScannerTypeDomain {
		encryptedPassword, err := encrypt.EncryptPassword(scanner.Password)
		if err != nil {
			log.Printf("Service: Error encrypting password: %v", err)
			return 0, ErrScannerOnCreate
		}
		scanner.Password = encryptedPassword
	}

	// Prepare schedule for persistence (calculate next run time)
	if scanner.Schedule != nil {
		s.prepareScheduleForPersistence(scanner.Schedule, 0) // scannerID will be set in repository
	}

	// Create scanner in repository
	scannerID, err := s.repo.Create(ctx, scanner)
	if err != nil {
		log.Printf("Service: Error creating scanner: %v", err)
		return 0, ErrScannerOnCreate
	}

	log.Printf("Service: Successfully created scanner with ID: %d, schedule type: %s",
		scannerID, scanner.Schedule.ScheduleType)
	return scannerID, nil
}

func (s *scannerService) GetScannerByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error) {
	log.Printf("Service: Getting scanner with ID: %d", scannerID)

	scanner, err := s.repo.GetByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error from repository: %v", err)
		return nil, err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scannerID)
		return nil, ErrScannerNotFound
	}

	// Decrypt password for VCenter and Domain scanners
	if scanner.ScanType == domain.ScannerTypeVCenter || scanner.ScanType == domain.ScannerTypeDomain {
		decryptedPassword, err := encrypt.DecryptPassword(scanner.Password)
		if err != nil {
			log.Printf("Service: Error decrypting password: %v", err)
			return nil, fmt.Errorf("failed to decrypt password: %w", err)
		}
		scanner.Password = decryptedPassword
	}

	log.Printf("Service: Successfully retrieved scanner: %+v", scanner)
	return scanner, nil
}

func (s *scannerService) UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Service: Updating scanner with ID: %d", scanner.ID)

	if scanner.ID == 0 {
		log.Printf("Service: Invalid scanner input - missing ID")
		return ErrInvalidScannerInput
	}

	// Get the existing scanner to determine what fields are being updated
	existingScanner, err := s.repo.GetByID(ctx, scanner.ID)
	if err != nil {
		log.Printf("Service: Error retrieving existing scanner: %v", err)
		return err
	}

	if existingScanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scanner.ID)
		return ErrScannerNotFound
	}

	// Merge the incoming scanner with existing data
	// Only update fields that are provided (non-zero values)
	updatedScanner := s.mergeScanner(*existingScanner, scanner)

	// Validate the updated scanner based on its type
	if err := s.validateScannerForUpdate(updatedScanner); err != nil {
		log.Printf("Service: Scanner validation failed: %v", err)
		return ErrInvalidScannerInput
	}

	// Set timestamps
	updatedScanner.UpdatedAt = time.Now()
	if existingScanner.CreatedAt.IsZero() {
		updatedScanner.CreatedAt = time.Now()
	} else {
		updatedScanner.CreatedAt = existingScanner.CreatedAt
	}

	// Encrypt password if it's being updated for VCenter or Domain scanners
	if updatedScanner.Password != existingScanner.Password &&
		(updatedScanner.ScanType == domain.ScannerTypeVCenter || updatedScanner.ScanType == domain.ScannerTypeDomain) {
		encryptedPassword, err := encrypt.EncryptPassword(updatedScanner.Password)
		if err != nil {
			log.Printf("Service: Error encrypting password: %v", err)
			return ErrScannerOnUpdate
		}
		updatedScanner.Password = encryptedPassword
	}

	// Prepare schedule for persistence (calculate next run time) if schedule is being updated
	if updatedScanner.Schedule != nil {
		s.prepareScheduleForPersistence(updatedScanner.Schedule, scanner.ID)
	}

	// Update scanner in repository
	err = s.repo.Update(ctx, updatedScanner)
	if err != nil {
		log.Printf("Service: Error updating scanner: %v", err)
		return ErrScannerOnUpdate
	}

	log.Printf("Service: Successfully updated scanner")
	return nil
}

// mergeScanner merges the incoming scanner updates with the existing scanner
// Only non-zero values from the incoming scanner will override existing values
func (s *scannerService) mergeScanner(existing, incoming domain.ScannerDomain) domain.ScannerDomain {
	// Start with the existing scanner
	merged := existing

	// Update fields only if they are provided (non-zero values)
	if incoming.Name != "" {
		merged.Name = incoming.Name
	}
	if incoming.ScanType != "" {
		merged.ScanType = incoming.ScanType
	}
	// Status is always updated (even if false)
	merged.Status = incoming.Status

	if incoming.UserID != "" {
		merged.UserID = incoming.UserID
	}
	if incoming.Type != "" {
		merged.Type = incoming.Type
	}
	if incoming.Target != "" {
		merged.Target = incoming.Target
	}
	if incoming.IP != "" {
		merged.IP = incoming.IP
	}
	if incoming.Subnet != 0 {
		merged.Subnet = incoming.Subnet
	}
	if incoming.StartIP != "" {
		merged.StartIP = incoming.StartIP
	}
	if incoming.EndIP != "" {
		merged.EndIP = incoming.EndIP
	}
	if incoming.Port != "" {
		merged.Port = incoming.Port
	}
	if incoming.Username != "" {
		merged.Username = incoming.Username
	}
	if incoming.Password != "" {
		merged.Password = incoming.Password
	}
	if incoming.Domain != "" {
		merged.Domain = incoming.Domain
	}
	if incoming.AuthenticationType != "" {
		merged.AuthenticationType = incoming.AuthenticationType
	}
	if incoming.Protocol != "" {
		merged.Protocol = incoming.Protocol
	}

	// Handle schedule updates
	if incoming.Schedule != nil {
		if merged.Schedule == nil {
			merged.Schedule = incoming.Schedule
		} else {
			// Merge schedule fields
			s.mergeSchedule(merged.Schedule, incoming.Schedule)
		}
	}

	return merged
}

// mergeSchedule merges schedule updates
func (s *scannerService) mergeSchedule(existing, incoming *domain.Schedule) {
	if incoming.ScheduleType != "" {
		existing.ScheduleType = incoming.ScheduleType
	}
	if incoming.FrequencyValue > 0 {
		existing.FrequencyValue = incoming.FrequencyValue
	}
	if incoming.FrequencyUnit != "" {
		existing.FrequencyUnit = incoming.FrequencyUnit
	}
	if !incoming.RunTime.IsZero() {
		existing.RunTime = incoming.RunTime
	}
	if incoming.Month > 0 {
		existing.Month = incoming.Month
	}
	if incoming.Week > 0 {
		existing.Week = incoming.Week
	}
	if incoming.Day > 0 {
		existing.Day = incoming.Day
	}
	if incoming.Hour >= 0 {
		existing.Hour = incoming.Hour
	}
	if incoming.Minute >= 0 {
		existing.Minute = incoming.Minute
	}
	existing.UpdatedAt = &[]time.Time{time.Now()}[0]
}

// validateScannerForUpdate validates scanner configuration for updates
func (s *scannerService) validateScannerForUpdate(scanner domain.ScannerDomain) error {
	// Basic validation
	if scanner.Name == "" {
		return fmt.Errorf("scanner name cannot be empty")
	}
	if scanner.ScanType == "" {
		return fmt.Errorf("scanner type cannot be empty")
	}

	// Validate based on scanner type
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		if err := s.validateNmapScanner(scanner); err != nil {
			return err
		}
	case domain.ScannerTypeVCenter:
		if err := s.validateVCenterScanner(scanner); err != nil {
			return err
		}
	case domain.ScannerTypeDomain:
		if err := s.validateDomainScanner(scanner); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid scanner type: %s", scanner.ScanType)
	}

	// Validate schedule if present
	if scanner.Schedule != nil {
		if err := s.validateSchedule(*scanner.Schedule); err != nil {
			return err
		}
	}

	return nil
}

func (s *scannerService) DeleteScanner(ctx context.Context, scannerID int64) error {
	log.Printf("Service: Deleting scanner with ID: %d", scannerID)

	// Check if scanner exists
	scanner, err := s.repo.GetByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error checking scanner existence: %v", err)
		return err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scannerID)
		return ErrScannerNotFound
	}

	// Delete scanner in repository
	err = s.repo.Delete(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error deleting scanner: %v", err)
		return ErrScannerOnDelete
	}

	log.Printf("Service: Successfully deleted scanner")
	return nil
}

func (s *scannerService) DeleteScanners(ctx context.Context, ids []string, filter *domain.ScannerFilter, exclude bool) (int, error) {
	log.Printf("Service: Deleting scanners with ids=%v, filter=%v, exclude=%v", ids, filter, exclude)

	// Special case: "All" in IDs list
	if len(ids) == 1 && ids[0] == "All" {
		// If "All" is specified with filters, use the filters to delete specific scanners
		if filter != nil {
			affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
				Filters: filter,
			})
			return checkDeletedScannersErrors(affected_rows, err)
		}

		// Delete all scanners without filters
		affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{})
		return checkDeletedScannersErrors(affected_rows, err)
	}

	// Convert string IDs to int64
	scannerIDs := make([]int64, 0, len(ids))
	for _, id := range ids {
		scannerID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		scannerIDs = append(scannerIDs, scannerID)
	}

	// Case with both filters and IDs
	if filter != nil {
		if exclude {
			// Delete scanners matching filter except those with the specified IDs
			affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
				Filters: filter,
				IDs:     scannerIDs,
				Exclude: true,
			})
			return checkDeletedScannersErrors(affected_rows, err)
		}

		// Delete scanners that match both specific IDs and filter criteria
		affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
			IDs:     scannerIDs,
			Filters: filter,
			Exclude: false,
		})
		return checkDeletedScannersErrors(affected_rows, err)
	}

	// Simple case: either include or exclude specific IDs
	if exclude {
		if len(scannerIDs) == 0 {
			affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{})
			return checkDeletedScannersErrors(affected_rows, err)
		}

		affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
			IDs:     scannerIDs,
			Exclude: true,
		})
		return checkDeletedScannersErrors(affected_rows, err)
	}

	if len(scannerIDs) == 0 {
		return 0, nil
	}

	affected_rows, err := s.repo.DeleteBatch(ctx, domain.DeleteParams{
		IDs: scannerIDs,
	})
	return checkDeletedScannersErrors(affected_rows, err)
}

func checkDeletedScannersErrors(affected_rows int, err error) (int, error) {
	if err != nil {
		log.Printf("Service: Error deleting scanners: %v", err)
		return 0, ErrScannerOnDelete
	}

	log.Printf("Service: Successfully deleted %d scanners", affected_rows)
	if affected_rows == 0 {
		return 0, ErrScannerNotFound
	}

	return affected_rows, nil
}

func (s *scannerService) ListScanners(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error) {
	log.Printf("Service: Listing scanners with filter: %+v, pagination: %+v", filter, pagination)

	// Get scanners from repository with filtering, sorting, and pagination
	scanners, totalCount, err := s.repo.List(ctx, filter, pagination)
	if err != nil {
		log.Printf("Service: Error listing scanners: %v", err)
		return nil, 0, err
	}

	// Decrypt passwords for VCenter and Domain scanners
	for i := range scanners {
		if scanners[i].ScanType == domain.ScannerTypeVCenter || scanners[i].ScanType == domain.ScannerTypeDomain {
			decryptedPassword, err := encrypt.DecryptPassword(scanners[i].Password)
			if err != nil {
				log.Printf("Service: Error decrypting password: %v", err)
				return nil, 0, fmt.Errorf("failed to decrypt password: %w", err)
			}
			scanners[i].Password = decryptedPassword
		}
	}

	log.Printf("Service: Successfully listed %d scanners (total: %d)", len(scanners), totalCount)
	return scanners, totalCount, nil
}

func (s *scannerService) UpdateScannerStatus(ctx context.Context, filter domain.ScannerFilter, ids []int64, status bool, exclude bool, updateAll bool) (int, error) {
	log.Printf("Service: Updating scanner status with params: filter=%+v, ids=%v, status=%v, exclude=%v, updateAll=%v",
		filter, ids, status, exclude, updateAll)

	// Create params struct for the new unified method
	params := domain.StatusUpdateParams{
		IDs:       ids,
		Filter:    filter,
		Status:    status,
		Exclude:   exclude,
		UpdateAll: updateAll,
	}

	// Call the unified repository method
	return s.repo.UpdateScannerStatus(ctx, params)
}
