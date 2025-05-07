package port

import (
	"context"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
)

// Repo defines the repository interface for scheduler operations
type Repo interface {
	// GetDueSchedules retrieves all scheduled scans that are due to run
	GetDueSchedules(ctx context.Context) ([]domain.ScheduledScan, error)

	// CreateScanJob creates a new scan job record
	CreateScanJob(ctx context.Context, job domain.ScanJob) (int64, error)

	// UpdateScanJobStatus updates the status of an existing scan job
	UpdateScanJobStatus(ctx context.Context, jobID int64, status domain.ScheduleStatus, progress int) error

	// CompleteScanJob marks a scan job as complete
	CompleteScanJob(ctx context.Context, jobID int64, status domain.ScheduleStatus) error

	// GetScannerWithSchedule retrieves a scanner with its associated schedule
	GetScannerWithSchedule(ctx context.Context, scannerID int64) (*domain.ScheduledScan, error)

	// GetActiveScanners retrieves all active scanners with their schedules
	GetActiveScanners(ctx context.Context) ([]domain.ScheduledScan, error)

	// UpdateScheduleNextRun updates the next run time for a schedule
	UpdateScheduleNextRun(ctx context.Context, scheduleID int64, nextRunTime string) error

	// GetScanJobDetails retrieves details for a specific scan job
	GetScanJobDetails(ctx context.Context, jobID int64) (*domain.ScanJob, error)
}

