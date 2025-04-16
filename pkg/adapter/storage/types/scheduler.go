package types

import (
	"time"
)

// ScanJobStatus represents the status of a scan job
type ScanJobStatus string

const (
	ScanJobStatusPending  ScanJobStatus = "Pending"
	ScanJobStatusRunning  ScanJobStatus = "Running"
	ScanJobStatusComplete ScanJobStatus = "Completed"
	ScanJobStatusFailed   ScanJobStatus = "Failed"
	ScanJobStatusError    ScanJobStatus = "Error"
)

// ScheduleFrequencyUnit represents the unit of time for schedule frequency
type ScheduleFrequencyUnit string

const (
	ScheduleFrequencyUnitMinute ScheduleFrequencyUnit = "minute"
	ScheduleFrequencyUnitHour   ScheduleFrequencyUnit = "hour"
	ScheduleFrequencyUnitDay    ScheduleFrequencyUnit = "day"
	ScheduleFrequencyUnitWeek   ScheduleFrequencyUnit = "week"
	ScheduleFrequencyUnitMonth  ScheduleFrequencyUnit = "month"
)

// ScanJobWithSchedule combines a scan job with its schedule information
type ScanJobWithSchedule struct {
	ScanJob  ScanJob
	Schedule Schedule
	Scanner  Scanner
}

// ScheduledScan represents a scanner with its schedule information
type ScheduledScan struct {
	Scanner     Scanner
	Schedule    Schedule
	NextRunTime time.Time
}
