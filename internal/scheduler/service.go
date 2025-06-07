package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
)

var (
	ErrSchedulerOnExecute   = errors.New("error on executing scheduled scan")
	ErrScanJobOnCreate      = errors.New("error on creating scan job")
	ErrScanJobOnUpdate      = errors.New("error on updating scan job")
	ErrScanJobOnCancel      = errors.New("error on cancelling scan job")
	ErrScheduleNotFound     = errors.New("schedule not found")
	ErrInvalidScheduleInput = errors.New("invalid schedule input")
	ErrScanJobNotRunning    = errors.New("scan job is not running")
	ErrScanJobNotFound      = errors.New("scan job not found")
)

type NmapScanner interface {
	ExecuteNmapScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error
	CancelScan(jobID int64) bool
	StatusScan(jobID int64) bool
}

type VCenterScanner interface {
	ExecuteVCenterScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error
	CancelScan(jobID int64) bool
	StatusScan(jobID int64) bool
}

type DomainScanner interface {
	ExecuteDomainScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error
	CancelScan(jobID int64) bool
	StatusScan(jobID int64) bool
}

type FirewallScanner interface {
	ExecuteFirewallScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error
	CancelScan(jobID int64) bool
	StatusScan(jobID int64) bool
}

// Enhanced schedulerService with multiple scanners
type schedulerService struct {
	repo            port.Repo
	scannerService  scannerPort.Service
	nmapScanner     NmapScanner
	vcenterScanner  VCenterScanner
	domainScanner   DomainScanner
	firewallScanner FirewallScanner
	cancelledJobs   map[int64]bool
	mutex           sync.Mutex // Mutex to protect concurrent access to cancelledJobs
}

// NewSchedulerService creates a new scheduler service with scanners
func NewSchedulerService(
	repo port.Repo,
	scannerService scannerPort.Service,
	nmapScanner NmapScanner,
	vcenterScanner VCenterScanner,
	domainScanner DomainScanner,
	firewallScanner FirewallScanner,
) port.Service {
	// Log the scanner implementations to help with debugging
	if nmapScanner == nil {
		log.Printf("Warning: NmapScanner implementation is nil")
	}
	if vcenterScanner == nil {
		log.Printf("Warning: VCenterScanner implementation is nil")
	}
	if domainScanner == nil {
		log.Printf("Warning: DomainScanner implementation is nil")
	}
	if firewallScanner == nil {
		log.Printf("Warning: FirewallScanner implementation is nil")
	}
	return &schedulerService{
		repo:            repo,
		scannerService:  scannerService,
		nmapScanner:     nmapScanner,
		vcenterScanner:  vcenterScanner,
		domainScanner:   domainScanner,
		firewallScanner: firewallScanner,
		cancelledJobs:   make(map[int64]bool),
	}
}

// ExecuteScheduledScan executes a scheduled scan and updates its job status and schedule.
func (s *schedulerService) ExecuteScheduledScan(ctx context.Context, scheduledScan domain.ScheduledScan) error {
	log.Printf("Scheduler Service: Executing scheduled scan for scanner ID: %d with schedule type: %s",
		scheduledScan.Scanner.ID, scheduledScan.Schedule.ScheduleType)

	// Create a new scan job record
	scanJob := domain.ScanJob{
		ScannerID: scheduledScan.Scanner.ID,
		Name:      fmt.Sprintf("%s - %s", scheduledScan.Scanner.Name, getScheduleDescription(scheduledScan.Schedule)),
		Type:      string(scheduledScan.Scanner.ScanType),
		Status:    domain.ScheduleStatusRunning,
		StartTime: time.Now(),
		Progress:  0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	jobID, err := s.repo.CreateScanJob(ctx, scanJob)
	if err != nil {
		log.Printf("Scheduler Service: Failed to create scan job: %v", err)
		return ErrScanJobOnCreate
	}
	log.Printf("Scheduler Service: Created scan job with ID: %d", jobID)

	// Handle next run time calculation based on schedule type
	var nextRunTimeStr *string
	switch scheduledScan.Schedule.ScheduleType {
	case scannerDomain.ScheduleTypeImmediately, scannerDomain.ScheduleTypeRunOnce:
		log.Printf("Scheduler Service: %s scan - will set next run time to NULL", scheduledScan.Schedule.ScheduleType)
		// Leave nextRunTimeStr as nil to set next_run_time to NULL

	case scannerDomain.ScheduleTypeRecurring:
		nextRunTime := CalculateNextRunTime(scheduledScan.Schedule, time.Now())
		formattedTime := nextRunTime.Format(time.RFC3339)
		nextRunTimeStr = &formattedTime
		log.Printf("Scheduler Service: Recurring scan - calculated next run time: %v", nextRunTime)

	default:
		log.Printf("Scheduler Service: Unknown schedule type %s, defaulting to recurring", scheduledScan.Schedule.ScheduleType)
		nextRunTime := CalculateNextRunTime(scheduledScan.Schedule, time.Now())
		formattedTime := nextRunTime.Format(time.RFC3339)
		nextRunTimeStr = &formattedTime
	}

	// Update the schedule's next run time (NULL for immediate/run-once, or calculated time for recurring)
	if err := s.repo.UpdateScheduleNextRun(ctx, scheduledScan.Schedule.ID, nextRunTimeStr); err != nil {
		log.Printf("Scheduler Service: Failed to update next run time: %v", err)
		// Continue execution, as this is not critical
	}

	// Execute the scan in a goroutine
	go func(scanner scannerDomain.ScannerDomain, jobID int64) {
		bgCtx := context.Background()

		// Update initial status
		if err := s.UpdateScanJob(bgCtx, jobID, domain.ScheduleStatusRunning, 10, false); err != nil {
			log.Printf("Scheduler Service: Failed to update scan job status: %v", err)
		}

		// Execute scan based on scanner type
		scanType := strings.ToUpper(strings.TrimSpace(scanner.ScanType))
		log.Printf("Scheduler Service: Executing %s scan for job ID: %d", scanType, jobID)

		var scanErr error
		switch scanType {
		case strings.ToUpper(scannerDomain.ScannerTypeNmap):
			scanErr = s.nmapScanner.ExecuteNmapScan(bgCtx, scanner, jobID)
		case strings.ToUpper(scannerDomain.ScannerTypeVCenter):
			if s.vcenterScanner == nil {
				scanErr = fmt.Errorf("VCenterScanner implementation is nil")
			} else {
				scanErr = s.vcenterScanner.ExecuteVCenterScan(bgCtx, scanner, jobID)
			}
		case strings.ToUpper(scannerDomain.ScannerTypeDomain):
			if s.domainScanner == nil {
				scanErr = fmt.Errorf("DomainScanner implementation is nil")
			} else {
				scanErr = s.domainScanner.ExecuteDomainScan(bgCtx, scanner, jobID)
			}
		case strings.ToUpper(scannerDomain.ScannerTypeFirewall):
			if s.firewallScanner == nil {
				scanErr = fmt.Errorf("FirewallScanner implementation is nil")
			} else {
				scanErr = s.firewallScanner.ExecuteFirewallScan(bgCtx, scanner, jobID)
			}
		default:
			scanErr = fmt.Errorf("unsupported scanner type: %s", scanner.ScanType)
		}

		// Update job status based on scan result
		var finalStatus domain.ScheduleStatus
		switch {
		case scanErr == nil:
			finalStatus = domain.ScheduleStatusComplete
		case errors.Is(scanErr, context.Canceled):
			finalStatus = domain.ScheduleStatusCancelled
			log.Printf("Scheduler Service: Scan cancelled for job ID: %d", jobID)
		default:
			finalStatus = domain.ScheduleStatusFailed
			log.Printf("Scheduler Service: Error executing scan: %v", scanErr)
		}

		if err := s.UpdateScanJob(bgCtx, jobID, finalStatus, 0, true); err != nil {
			log.Printf("Scheduler Service: Failed to update job status to %s: %v", finalStatus, err)
		}
		log.Printf("Scheduler Service: Scan job ID %d completed with status: %s", jobID, finalStatus)
	}(scheduledScan.Scanner, jobID)

	return nil
}

// Helper function to generate a descriptive name for the scan based on schedule type
func getScheduleDescription(schedule scannerDomain.Schedule) string {
	switch schedule.ScheduleType {
	case scannerDomain.ScheduleTypeImmediately:
		return "Immediate Run"
	case scannerDomain.ScheduleTypeRunOnce:
		return "One-time Run"
	case scannerDomain.ScheduleTypeRecurring:
		return "Scheduled Run"
	default:
		return "Scheduled Run"
	}
}

// GetDueSchedules retrieves all scheduled scans that are due to run
func (s *schedulerService) GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error) {
	log.Printf("Scheduler Service: Retrieving due schedules")
	return s.repo.GetDueSchedules(ctx)
}

// UpdateScanJob updates the status, progress, and optionally end time of a scan job.
func (s *schedulerService) UpdateScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int, setEndTime bool) error {
	log.Printf("Scheduler Service: Updating scan job ID: %d to status: %s with progress: %d, setEndTime: %v", jobID, status, progress, setEndTime)

	err := s.repo.UpdateScanJob(ctx, jobID, status, progress, setEndTime)
	if err != nil {
		// If there were no rows affected, the job might have been already completed
		// This can happen in a race condition between cancellation and normal completion
		if strings.Contains(err.Error(), "scan job not found") {
			log.Printf("Scheduler Service: Job ID %d was already completed", jobID)
			return ErrScanJobNotFound
		}
		return err
	}
	return nil
}

// CalculateNextRunTime determines when a scheduled scan should next run
func (s *schedulerService) CalculateNextRunTime(schedule scannerDomain.Schedule) string {
	nextRunTime := CalculateNextRunTime(schedule, time.Now())
	return nextRunTime.Format(time.RFC3339)
}

// CancelScanJob cancels a running scan job and marks it as cancelled.
func (s *schedulerService) CancelScanJob(ctx context.Context, jobID int64) error {
	log.Printf("Scheduler Service: Cancelling scan job ID: %d", jobID)

	// Get job details to determine scanner type
	job, err := s.repo.GetScanJobDetails(ctx, jobID)
	if err != nil {
		log.Printf("Scheduler Service: Error getting job details: %v", err)
		return err
	}

	// Normalize job type for comparison and log
	jobType := strings.ToUpper(strings.TrimSpace(job.Type))
	log.Printf("Scheduler Service: Cancelling %s scan job", jobType)

	// Determine scanner type and use appropriate cancel method
	var cancelled bool
	switch jobType {
	case strings.ToUpper(scannerDomain.ScannerTypeNmap):
		cancelled = s.nmapScanner.CancelScan(jobID)
	case strings.ToUpper(scannerDomain.ScannerTypeVCenter):
		if s.vcenterScanner == nil {
			log.Printf("Scheduler Service: VCenterScanner implementation is nil")
			return fmt.Errorf("VCenterScanner implementation is nil")
		}
		cancelled = s.vcenterScanner.CancelScan(jobID)
	case strings.ToUpper(scannerDomain.ScannerTypeDomain):
		if s.domainScanner == nil {
			log.Printf("Scheduler Service: DomainScanner implementation is nil")
			return fmt.Errorf("DomainScanner implementation is nil")
		}
		cancelled = s.domainScanner.CancelScan(jobID)
	case strings.ToUpper(scannerDomain.ScannerTypeFirewall):
		if s.firewallScanner == nil {
			log.Printf("Scheduler Service: FirewallScanner implementation is nil")
			return fmt.Errorf("FirewallScanner implementation is nil")
		}
		cancelled = s.firewallScanner.CancelScan(jobID)
	default:
		log.Printf("Scheduler Service: Unknown scanner type %s for job ID %d", job.Type, jobID)
		return fmt.Errorf("unknown scanner type: %s", job.Type)
	}

	if !cancelled {
		log.Printf("Scheduler Service: Failed to cancel scan job ID: %d", jobID)
		return ErrScanJobOnCancel
	}

	// Mark this job as cancelled so we don't try to update it again
	s.mutex.Lock()
	s.cancelledJobs[jobID] = true
	s.mutex.Unlock()

	// Update job status to cancelled
	err = s.UpdateScanJob(ctx, jobID, domain.ScheduleStatusCancelled, 0, true)
	if err != nil {
		log.Printf("Scheduler Service: Error updating job status after cancellation: %v", err)
		if strings.Contains(err.Error(), "scan job not found") {
			log.Printf("Scheduler Service: Job ID %d was already completed", jobID)
			return ErrScanJobNotFound
		}
		return err
	}

	log.Printf("Scheduler Service: Successfully cancelled scan job ID: %d", jobID)
	return nil
}

// CreateScanJob creates a new scan job record
func (s *schedulerService) CreateScanJob(ctx context.Context, job domain.ScanJob) (int64, error) {
	log.Printf("Scheduler Service: Creating scan job for scanner ID: %d", job.ScannerID)

	// Create a new scan job record via the repository
	jobID, err := s.repo.CreateScanJob(ctx, job)
	if err != nil {
		log.Printf("Scheduler Service: Failed to create scan job: %v", err)
		return 0, ErrScanJobOnCreate
	}

	log.Printf("Scheduler Service: Created scan job with ID: %d", jobID)
	return jobID, nil
}

// ExecuteManualScan runs a scan manually for the given scanner
func (s *schedulerService) ExecuteManualScan(ctx context.Context, scanner scannerDomain.ScannerDomain, jobID int64) error {
	log.Printf("Scheduler Service: Executing manual scan for scanner ID: %d", scanner.ID)

	// Check if the scanner is valid
	if scanner.ID == 0 {
		return errors.New("invalid scanner ID")
	}

	// Log the scanner type to help with debugging
	log.Printf("Scheduler Service: Manual scan for scanner type: '%s'", scanner.ScanType)
	log.Printf("Scheduler Service: NMAP constant: '%s', VCENTER constant: '%s', DOMAIN constant: '%s'",
		scannerDomain.ScannerTypeNmap, scannerDomain.ScannerTypeVCenter, scannerDomain.ScannerTypeDomain)

	// Normalize scanner type for comparison
	scanType := strings.TrimSpace(strings.ToUpper(scanner.ScanType))
	log.Printf("Scheduler Service: Normalized scanner type for comparison: '%s'", scanType)

	// Execute scan based on scanner type
	switch scanType {
	case strings.ToUpper(scannerDomain.ScannerTypeNmap):
		log.Printf("Scheduler Service: Executing NMAP manual scan for job ID: %d", jobID)
		return s.nmapScanner.ExecuteNmapScan(ctx, scanner, jobID)
	case strings.ToUpper(scannerDomain.ScannerTypeVCenter):
		log.Printf("Scheduler Service: Executing VCenter manual scan for job ID: %d", jobID)
		if s.vcenterScanner == nil {
			return fmt.Errorf("VCenterScanner implementation is nil")
		}
		return s.vcenterScanner.ExecuteVCenterScan(ctx, scanner, jobID)
	case strings.ToUpper(scannerDomain.ScannerTypeDomain):
		log.Printf("Scheduler Service: Executing Domain manual scan for job ID: %d", jobID)
		if s.domainScanner == nil {
			return fmt.Errorf("DomainScanner implementation is nil")
		}
		return s.domainScanner.ExecuteDomainScan(ctx, scanner, jobID)
	case strings.ToUpper(scannerDomain.ScannerTypeFirewall):
		log.Printf("Scheduler Service: Executing Firewall manual scan for job ID: %d", jobID)
		if s.firewallScanner == nil {
			return fmt.Errorf("FirewallScanner implementation is nil")
		}
		return s.firewallScanner.ExecuteFirewallScan(ctx, scanner, jobID)
	default:
		return fmt.Errorf("unsupported scanner type: %s", scanner.ScanType)
	}
}
