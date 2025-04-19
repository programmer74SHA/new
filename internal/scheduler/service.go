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

// Define the NmapScanner interface for executing scans
type NmapScanner interface {
	ExecuteNmapScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error
	CancelScan(jobID int64) bool
	StatusScan(jobID int64) bool
}

// Enhanced schedulerService with Nmap scanner
type schedulerService struct {
	repo           port.Repo
	scannerService scannerPort.Service
	nmapScanner    NmapScanner
	cancelledJobs  map[int64]bool // Track jobs that have been cancelled
	mutex          sync.Mutex     // Mutex to protect concurrent access to cancelledJobs
}

// NewSchedulerService creates a new scheduler service with Nmap scanner
func NewSchedulerService(repo port.Repo, scannerService scannerPort.Service, nmapScanner NmapScanner) port.Service {
	return &schedulerService{
		repo:           repo,
		scannerService: scannerService,
		nmapScanner:    nmapScanner,
		cancelledJobs:  make(map[int64]bool),
	}
}

// ExecuteScheduledScan runs a scheduled scan
func (s *schedulerService) ExecuteScheduledScan(ctx context.Context, scheduledScan domain.ScheduledScan) error {
	log.Printf("Scheduler Service: Executing scheduled scan for scanner ID: %d with details: %+v",
		scheduledScan.Scanner.ID, scheduledScan.Scanner)

	// Create a new scan job record
	scanJob := domain.ScanJob{
		ScannerID: scheduledScan.Scanner.ID,
		Name:      fmt.Sprintf("%s - Scheduled Run", scheduledScan.Scanner.Name),
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

	// Update the scan job with the job ID
	scanJob.ID = jobID
	log.Printf("Scheduler Service: Created scan job with ID: %d", jobID)

	// Calculate the next run time based on the schedule and CURRENT time
	// This ensures we're calculating from now, not from the previous scheduled time
	currentTime := time.Now()
	nextRunTime := domain.CalculateNextRunTime(scheduledScan.Schedule, currentTime)

	log.Printf("Scheduler Service: Current time: %v", currentTime)
	log.Printf("Scheduler Service: Calculated next run time: %v", nextRunTime)

	// Format time with RFC3339 to preserve timezone information
	formattedNextRunTime := nextRunTime.Format(time.RFC3339)
	log.Printf("Scheduler Service: Formatted next run time: %s", formattedNextRunTime)

	// Update the schedule with the next run time
	err = s.repo.UpdateScheduleNextRun(ctx, scheduledScan.Schedule.ID, formattedNextRunTime)
	if err != nil {
		log.Printf("Scheduler Service: Failed to update next run time: %v", err)
		// Continue execution, this is not a critical failure
	}

	// Execute the appropriate scan based on scanner type
	go func(scanner scannerDomain.ScannerDomain, jobID int64) {
		// Create a new context for the background operation
		bgCtx := context.Background()

		// First update status to show scan is starting
		err := s.UpdateScanJobStatus(bgCtx, jobID, domain.ScheduleStatusRunning, 10)
		if err != nil {
			log.Printf("Scheduler Service: Failed to update scan job status: %v", err)
		}

		// Execute Nmap scan for NMAP scanner type
		var scanErr error
		if scanner.ScanType == scannerDomain.ScannerTypeNmap {
			scanErr = s.nmapScanner.ExecuteNmapScan(bgCtx, scanner, jobID)
		} else {
			scanErr = fmt.Errorf("unsupported scanner type: %s", scanner.ScanType)
		}

		// Update job status based on scan result
		if scanErr != nil {
			log.Printf("Scheduler Service: Error executing scan: %v", scanErr)
			err := s.CompleteScanJob(bgCtx, jobID, domain.ScheduleStatusFailed)
			if err != nil {
				log.Printf("Scheduler Service: Failed to update job status to failed: %v", err)
			}
		} else {
			err := s.CompleteScanJob(bgCtx, jobID, domain.ScheduleStatusComplete)
			if err != nil {
				log.Printf("Scheduler Service: Failed to update job status to complete: %v", err)
			}
		}

		log.Printf("Scheduler Service: Scan job ID %d completed with status: %v", jobID, scanErr == nil)
	}(scheduledScan.Scanner, jobID)

	return nil
}

// GetDueSchedules retrieves all scheduled scans that are due to run
func (s *schedulerService) GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error) {
	log.Printf("Scheduler Service: Retrieving due schedules")
	return s.repo.GetDueSchedules(ctx)
}

// UpdateScanJobStatus updates the status of an existing scan job
func (s *schedulerService) UpdateScanJobStatus(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int) error {
	log.Printf("Scheduler Service: Updating scan job ID: %d to status: %s with progress: %d", jobID, status, progress)
	return s.repo.UpdateScanJobStatus(ctx, jobID, status, progress)
}

// CompleteScanJob marks a scan job as complete
func (s *schedulerService) CompleteScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus) error {
	log.Printf("Scheduler Service: Completing scan job ID: %d with status: %s", jobID, status)
	err := s.repo.CompleteScanJob(ctx, jobID, status)
	if err != nil {
		// If there were no rows affected, the job might have been already completed
		// This can happen in the race condition between cancellation and normal completion
		if strings.Contains(err.Error(), "no rows affected") {
			log.Printf("Scheduler Service: Job ID %d was already completed", jobID)
			return ErrScanJobNotFound
		}
		return err
	}
	return nil
}

// CalculateNextRunTime determines when a scheduled scan should next run
func (s *schedulerService) CalculateNextRunTime(schedule scannerDomain.Schedule) string {
	nextRunTime := domain.CalculateNextRunTime(schedule, time.Now())
	return nextRunTime.Format(time.RFC3339)
}

// CancelScanJob cancels a running scan job
func (s *schedulerService) CancelScanJob(ctx context.Context, jobID int64) error {
	log.Printf("Scheduler Service: Cancelling scan job ID: %d", jobID)

	// Check if the job is running in the nmap scanner
	if !s.nmapScanner.StatusScan(jobID) {
		log.Printf("Scheduler Service: Scan job ID %d is not currently running", jobID)
		return ErrScanJobNotRunning
	}

	// Attempt to cancel the scan
	cancelled := s.nmapScanner.CancelScan(jobID)
	if !cancelled {
		log.Printf("Scheduler Service: Failed to cancel scan job ID: %d", jobID)
		return ErrScanJobOnCancel
	}

	// Mark this job as cancelled so we don't try to update it again
	s.mutex.Lock()
	s.cancelledJobs[jobID] = true
	s.mutex.Unlock()

	// Update job status to cancelled (using the new Cancelled status)
	err := s.repo.CompleteScanJob(ctx, jobID, domain.ScheduleStatusCancelled)
	if err != nil {
		log.Printf("Scheduler Service: Error updating job status after cancellation: %v", err)
		return err
	}

	log.Printf("Scheduler Service: Successfully cancelled scan job ID: %d", jobID)
	return nil
}

// CreateScanJob creates a new scan job record (implement as public)
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

	// Execute scan based on scanner type
	if scanner.ScanType == scannerDomain.ScannerTypeNmap {
		// Execute Nmap scan
		return s.nmapScanner.ExecuteNmapScan(ctx, scanner, jobID)
	}

	return fmt.Errorf("unsupported scanner type: %s", scanner.ScanType)
}
