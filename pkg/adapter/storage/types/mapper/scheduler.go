package mapper

import (
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

// ScanJobDomain2Storage converts a domain ScanJob to a storage ScanJob
func ScanJobDomain2Storage(job domain.ScanJob) *types.ScanJob {
	var endTime *time.Time
	var progress *int

	if job.EndTime != nil {
		endTime = job.EndTime
	}

	progress = &job.Progress

	return &types.ScanJob{
		ID:        job.ID,
		ScannerID: job.ScannerID,
		Name:      job.Name,
		Type:      job.Type,
		Status:    string(job.Status),
		StartTime: job.StartTime,
		EndTime:   endTime,
		Progress:  progress,
	}
}

// ScanJobStorage2Domain converts a storage ScanJob to a domain ScanJob
// func ScanJobStorage2Domain(job types.ScanJob) (*domain.ScanJob, error) {
// 	var endTime *time.Time
// 	var progress int
// 	if job.EndTime != nil {
// 		endTime = job.EndTime
// 	}
// 	if job.Progress != nil {
// 		progress = *job.Progress
// 	}
// 	status := domain.ScheduleStatus(job.Status)
// 	return &domain.ScanJob{
// 		ID:        job.ID,
// 		ScannerID: job.ScannerID,
// 		Name:      job.Name,
// 		Type:      job.Type,
// 		Status:    status,
// 		StartTime: job.StartTime,
// 		EndTime:   endTime,
// 		Progress:  progress,
// 		CreatedAt: job.StartTime,
// 	}, nil
// }

// ScheduledScanStorage2Domain converts storage types to a domain ScheduledScan
func ScheduledScanStorage2Domain(scanner types.Scanner, schedule types.Schedule, nextRunTime time.Time) *domain.ScheduledScan {
	// Convert scanner to domain model
	scannerDomainModel := &scannerDomain.ScannerDomain{
		ID:        scanner.ID,
		Name:      scanner.Name,
		ScanType:  scanner.ScanType,
		Status:    scanner.Status,
		CreatedAt: scanner.CreatedAt,
	}

	// Set optional fields
	if scanner.UserID != nil {
		scannerDomainModel.UserID = *scanner.UserID
	}

	if scanner.UpdatedAt != nil {
		scannerDomainModel.UpdatedAt = *scanner.UpdatedAt
	}

	if scanner.DeletedAt != nil {
		scannerDomainModel.DeletedAt = *scanner.DeletedAt
	}

	return &domain.ScheduledScan{
		Scanner: *scannerDomainModel,
		Schedule: scannerDomain.Schedule{
			ID:             schedule.ID,
			ScannerID:      schedule.ScannerID,
			FrequencyValue: schedule.FrequencyValue,
			FrequencyUnit:  schedule.FrequencyUnit,
			Month:          schedule.Month,
			Week:           schedule.Week,
			Day:            schedule.Day,
			Hour:           schedule.Hour,
			Minute:         schedule.Minute,
		},
		NextRunTime: nextRunTime,
	}
}
