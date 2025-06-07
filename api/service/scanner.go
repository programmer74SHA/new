package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
	schedulerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/domain"
	schedulerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler/port"
)

var (
	ErrScannerOnCreate     = scanner.ErrScannerOnCreate
	ErrScannerOnUpdate     = scanner.ErrScannerOnUpdate
	ErrScannerOnDelete     = scanner.ErrScannerOnDelete
	ErrScannerNotFound     = scanner.ErrScannerNotFound
	ErrInvalidScannerInput = scanner.ErrInvalidScannerInput
)

type ScannerService struct {
	service                  scannerPort.Service
	schedulerService         schedulerPort.Service
	concreteSchedulerService interface{} // For accessing internal methods
}

func NewScannerService(srv scannerPort.Service) *ScannerService {
	return &ScannerService{
		service: srv,
	}
}

// SetSchedulerService sets the scheduler service reference
func (s *ScannerService) SetSchedulerService(schedulerSrv schedulerPort.Service) {
	s.schedulerService = schedulerSrv
	// Store the concrete implementation for internal method access
	s.concreteSchedulerService = schedulerSrv
}

// CreateScanner creates a new scanner with schedule type support
func (s *ScannerService) CreateScanner(ctx context.Context, req *pb.CreateScannerRequest) (*pb.CreateScannerResponse, error) {
	log.Printf("API Service: Creating scanner")

	// Map request to domain model
	scanner := domain.ScannerDomain{
		Name:               req.GetName(),
		ScanType:           req.GetScanType(),
		Status:             req.GetStatus(),
		UserID:             req.GetUserId(),
		Type:               req.GetType(),
		Target:             req.GetTarget(),
		IP:                 req.GetIp(),
		Subnet:             req.GetSubnet(),
		StartIP:            req.GetStartIp(),
		EndIP:              req.GetEndIp(),
		Port:               req.GetPort(),
		Username:           req.GetUsername(),
		Password:           req.GetPassword(),
		ApiKey:             req.GetApiKey(),
		Domain:             req.GetDomain(),
		AuthenticationType: req.GetAuthenticationType(),
		Protocol:           req.GetProtocol(),
	}

	// Map schedule from request
	if req.GetSchedule() != nil {
		schedule := &domain.Schedule{
			ScheduleType:   domain.ScheduleType(req.GetSchedule().GetScheduleType()),
			FrequencyValue: req.GetSchedule().GetFrequencyValue(),
			FrequencyUnit:  req.GetSchedule().GetFrequencyUnit(),
			Month:          req.GetSchedule().GetMonth(),
			Week:           req.GetSchedule().GetWeek(),
			Day:            req.GetSchedule().GetDay(),
			Hour:           req.GetSchedule().GetHour(),
			Minute:         req.GetSchedule().GetMinute(),
		}

		// Parse RunTime if provided
		if runTimeStr := req.GetSchedule().GetRunTime(); runTimeStr != "" {
			runTime, err := parseRunTime(runTimeStr)
			if err != nil {
				return &pb.CreateScannerResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("failed to parse RunTime: %v", err),
				}, err
			}
			schedule.RunTime = runTime
		}

		scanner.Schedule = schedule
	}

	// Call internal service - all validation will be done there
	id, err := s.service.CreateScanner(ctx, scanner)
	if err != nil {
		return &pb.CreateScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Return success response
	return &pb.CreateScannerResponse{
		Success: true,
		Scanner: &pb.Scanner{
			Id:       strconv.FormatInt(id, 10),
			Name:     scanner.Name,
			ScanType: scanner.ScanType,
			Status:   scanner.Status,
		},
	}, nil
}

func (s *ScannerService) GetScanner(ctx context.Context, req *pb.GetScannerRequest) (*pb.GetScannerResponse, error) {
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.GetScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Get scanner from internal service
	scanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		return &pb.GetScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Map domain model to response
	pbScanner := mapDomainToProto(scanner)

	return &pb.GetScannerResponse{
		Success: true,
		Scanner: pbScanner,
	}, nil
}

func (s *ScannerService) UpdateScanner(ctx context.Context, req *pb.UpdateScannerRequest) (*pb.UpdateScannerResponse, error) {
	log.Printf("API Service: Updating scanner")

	// Parse and validate scanner ID
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.UpdateScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Create scanner domain object with only the fields that are being updated
	scanner := domain.ScannerDomain{
		ID:                 id,
		Name:               req.GetName(),
		ScanType:           req.GetScanType(),
		Status:             req.GetStatus(),
		UserID:             req.GetUserId(),
		Type:               req.GetType(),
		Target:             req.GetTarget(),
		IP:                 req.GetIp(),
		Subnet:             req.GetSubnet(),
		StartIP:            req.GetStartIp(),
		EndIP:              req.GetEndIp(),
		Port:               req.GetPort(),
		Username:           req.GetUsername(),
		Password:           req.GetPassword(),
		ApiKey:             req.GetApiKey(),
		Domain:             req.GetDomain(),
		AuthenticationType: req.GetAuthenticationType(),
		Protocol:           req.GetProtocol(),
	}

	// Handle schedule updates if present
	if hasScheduleUpdates(req) {
		schedule := &domain.Schedule{
			ScannerID:      id,
			ScheduleType:   domain.ScheduleType(req.GetScheduleType()),
			FrequencyValue: req.GetFrequencyValue(),
			FrequencyUnit:  req.GetFrequencyUnit(),
			Month:          req.GetMonth(),
			Week:           req.GetWeek(),
			Day:            req.GetDay(),
			Hour:           req.GetHour(),
			Minute:         req.GetMinute(),
		}

		// Parse RunTime if provided
		if req.GetRunTime() != "" {
			runTime, err := parseRunTime(req.GetRunTime())
			if err != nil {
				return &pb.UpdateScannerResponse{
					Success:      false,
					ErrorMessage: fmt.Sprintf("failed to parse RunTime: %v", err),
				}, err
			}
			schedule.RunTime = runTime
		}

		scanner.Schedule = schedule
	}

	// Call internal service to update scanner
	if err := s.service.UpdateScanner(ctx, scanner); err != nil {
		return &pb.UpdateScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Get the updated scanner to return accurate data
	updatedScanner, err := s.service.GetScannerByID(ctx, id)
	if err != nil {
		// If we can't get the updated scanner, return basic info
		return &pb.UpdateScannerResponse{
			Success: true,
			Scanner: &pb.Scanner{
				Id:       req.GetId(),
				Name:     req.GetName(),
				ScanType: req.GetScanType(),
				Status:   req.GetStatus(),
			},
		}, nil
	}

	// Build and return success response with updated scanner data
	return &pb.UpdateScannerResponse{
		Success: true,
		Scanner: mapDomainToProto(updatedScanner),
	}, nil
}

func (s *ScannerService) DeleteScanner(ctx context.Context, req *pb.DeleteScannerRequest) (*pb.DeleteScannerResponse, error) {
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.DeleteScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	if err := s.service.DeleteScanner(ctx, id); err != nil {
		return &pb.DeleteScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.DeleteScannerResponse{
		Success: true,
	}, nil
}

func (s *ScannerService) DeleteScanners(ctx context.Context, req *pb.DeleteScannersRequest) (*pb.DeleteScannersResponse, error) {
	// Convert the filter from proto to domain if present
	var filter *domain.ScannerFilter
	if req.Filter != nil {
		var status bool
		hasStatusFilter := req.Filter.GetHasStatusFilter()

		if hasStatusFilter {
			status = req.Filter.GetStatus()
		}

		f := domain.ScannerFilter{
			Name:     req.Filter.GetName(),
			ScanType: req.Filter.GetType(),
		}

		if hasStatusFilter {
			f.Status = &status
		}

		filter = &f
	}

	deletedCount, err := s.service.DeleteScanners(ctx, req.Ids, filter, req.GetExclude())
	if err != nil {
		return &pb.DeleteScannersResponse{
			Success:      false,
			ErrorMessage: err.Error(),
			DeletedCount: 0,
		}, err
	}

	return &pb.DeleteScannersResponse{
		Success:      true,
		DeletedCount: int32(deletedCount),
	}, nil
}

func (s *ScannerService) ListScanners(
	ctx context.Context,
	req *pb.ListScannersRequest,
	limit int,
	page int,
	sortField string,
	sortOrder string,
) (*pb.ListScannersResponse, int, error) {
	// Create filter
	filter := domain.ScannerFilter{
		Name:     req.GetName(),
		ScanType: req.GetScanType(),
	}

	// Use the has_status_filter field directly
	if req.GetHasStatusFilter() {
		status := req.GetStatus()
		filter.Status = &status
		log.Printf("Service: Status filter explicitly provided: %v", status)
	} else {
		log.Printf("Service: No status filter provided, will fetch all scanners")
	}

	// Create pagination options
	pagination := domain.Pagination{
		Limit:     limit,
		Page:      page,
		SortField: sortField,
		SortOrder: sortOrder,
	}

	// Call internal service
	scanners, totalCount, err := s.service.ListScanners(ctx, filter, pagination)
	if err != nil {
		return nil, 0, err
	}

	// Convert domain objects to protobuf objects
	pbScanners := make([]*pb.Scanner, 0)

	for _, scanner := range scanners {
		// Make a copy to avoid modifying the original
		scannerCopy := scanner
		pbScanner := mapDomainToProto(&scannerCopy)

		// Ensure status is set explicitly
		pbScanner.Status = scanner.Status

		pbScanners = append(pbScanners, pbScanner)
	}

	return &pb.ListScannersResponse{
		Scanners:   pbScanners,
		TotalCount: int32(totalCount),
		Success:    true,
	}, totalCount, nil
}

func (s *ScannerService) UpdateScannerStatus(ctx context.Context, req *pb.UpdateScannerStatusRequest) (*pb.UpdateScannerStatusResponse, error) {
	log.Printf("API Service: Update scanner status request: %+v", req)

	// Parse IDs if provided
	var ids []int64
	for _, idStr := range req.GetIds() {
		// Special case for "all"
		if idStr == "all" || idStr == "All" {
			req.UpdateAll = true
			ids = []int64{} // empty the IDs list
			break
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	// Create filter from request
	filter := domain.ScannerFilter{}
	if req.GetFilter() != nil {
		filter.Name = req.GetFilter().GetName()

		// Handle case insensitivity for scan_type
		scanType := req.GetFilter().GetType()
		if strings.EqualFold(scanType, "domain") {
			scanType = domain.ScannerTypeDomain
		} else if strings.EqualFold(scanType, "nmap") {
			scanType = domain.ScannerTypeNmap
		} else if strings.EqualFold(scanType, "vcenter") {
			scanType = domain.ScannerTypeVCenter
		}
		filter.ScanType = scanType
	}

	// Call internal service method with all parameters
	updatedCount, err := s.service.UpdateScannerStatus(
		ctx,
		filter,
		ids,
		req.GetStatus(),
		req.GetExclude(),
		req.GetUpdateAll(),
	)

	if err != nil {
		return &pb.UpdateScannerStatusResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.UpdateScannerStatusResponse{
		Success:      true,
		UpdatedCount: int32(updatedCount),
	}, nil
}

// CancelScanJob cancels a running scan job
func (s *ScannerService) CancelScanJob(ctx context.Context, req *pb.CancelScanJobRequest) (*pb.CancelScanJobResponse, error) {
	// Check if scheduler service is set
	if s.schedulerService == nil {
		return &pb.CancelScanJobResponse{
			Success:      false,
			ErrorMessage: "Scheduler service not available",
		}, nil
	}

	// Parse job ID
	jobID, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.CancelScanJobResponse{
			Success:      false,
			ErrorMessage: "Invalid job ID",
		}, ErrInvalidScannerInput
	}

	// Call scheduler service to cancel the job
	err = s.schedulerService.CancelScanJob(ctx, jobID)
	if err != nil {
		return &pb.CancelScanJobResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.CancelScanJobResponse{
		Success: true,
	}, nil
}

// RunScanNow handles HTTP requests to immediately execute a scan for a scanner
func (s *ScannerService) RunScanNow(ctx context.Context, req *pb.RunScanNowRequest) (*pb.RunScanNowResponse, error) {
	log.Printf("Service: Running immediate scan for scanner ID: %s", req.GetScannerId())

	// Parse scanner ID
	scannerID, err := strconv.ParseInt(req.GetScannerId(), 10, 64)
	if err != nil {
		log.Printf("Service: Invalid scanner ID: %v", err)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Get the scanner details
	scanner, err := s.service.GetScannerByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error retrieving scanner: %v", err)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found with ID: %d", scannerID)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scanner not found",
		}, ErrScannerNotFound
	}

	// Log the scanner type for debugging
	log.Printf("Service: Scanner has type: '%s'", scanner.ScanType)

	// Check if scheduler service is set
	if s.schedulerService == nil {
		log.Printf("Service: Scheduler service not available")
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scheduler service not available",
		}, errors.New("scheduler service not available")
	}

	// Create a scan job record using the concrete implementation
	var jobID int64
	if scheduler, ok := s.concreteSchedulerService.(interface {
		CreateScanJob(ctx context.Context, job schedulerDomain.ScanJob) (int64, error)
	}); ok {
		scanJob := schedulerDomain.ScanJob{
			ScannerID: scannerID,
			Name:      fmt.Sprintf("%s - Manual Run", scanner.Name),
			Type:      string(scanner.ScanType),
			Status:    schedulerDomain.ScheduleStatusRunning,
			StartTime: time.Now(),
			Progress:  0,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		var createJobErr error
		jobID, createJobErr = scheduler.CreateScanJob(ctx, scanJob)
		if createJobErr != nil {
			log.Printf("Service: Error creating scan job: %v", createJobErr)
			return &pb.RunScanNowResponse{
				Success:      false,
				ErrorMessage: "Failed to create scan job: " + createJobErr.Error(),
			}, createJobErr
		}
	} else {
		log.Printf("Service: Cannot create scan job - scheduler service doesn't support required methods")
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scheduler service missing required capabilities",
		}, errors.New("scheduler service missing required capabilities")
	}

	// Execute the scan in a goroutine
	go func() {
		// Create a new context for the background operation
		bgCtx := context.Background()

		// Update job status to show scan is starting
		if scheduler, ok := s.concreteSchedulerService.(interface {
			UpdateScanJobStatus(ctx context.Context, jobID int64, status schedulerDomain.ScheduleStatus, progress int) error
		}); ok {
			err := scheduler.UpdateScanJobStatus(bgCtx, jobID, schedulerDomain.ScheduleStatusRunning, 10)
			if err != nil {
				log.Printf("Service: Failed to update scan job status: %v", err)
			}
		}

		// Execute the scan via the scheduler service's ExecuteManualScan method
		scanErr := s.schedulerService.ExecuteManualScan(bgCtx, *scanner, jobID)

		// Update job status based on scan result
		if completer, ok := s.concreteSchedulerService.(interface {
			CompleteScanJob(ctx context.Context, jobID int64, status schedulerDomain.ScheduleStatus) error
		}); ok {
			if scanErr != nil {
				log.Printf("Service: Error executing scan: %v", scanErr)
				err := completer.CompleteScanJob(bgCtx, jobID, schedulerDomain.ScheduleStatusFailed)
				if err != nil {
					log.Printf("Service: Failed to update job status to failed: %v", err)
				}
			} else {
				err := completer.CompleteScanJob(bgCtx, jobID, schedulerDomain.ScheduleStatusComplete)
				if err != nil {
					log.Printf("Service: Failed to update job status to complete: %v", err)
				}
			}
		}

		log.Printf("Service: Manual scan job ID %d completed with status: %v", jobID, scanErr == nil)
	}()

	return &pb.RunScanNowResponse{
		Success: true,
		JobId:   jobID,
	}, nil
}

// Helper functions

func hasScheduleUpdates(req *pb.UpdateScannerRequest) bool {
	return req.GetScheduleType() != "" ||
		req.GetFrequencyValue() > 0 ||
		req.GetFrequencyUnit() != "" ||
		req.GetRunTime() != "" ||
		req.GetHour() >= 0 ||
		req.GetMinute() >= 0 ||
		req.GetDay() > 0 ||
		req.GetWeek() > 0 ||
		req.GetMonth() > 0
}

func parseRunTime(runTimeStr string) (time.Time, error) {
	// Try parsing with different formats in order of preference
	formats := []string{
		"2006-01-02 15:04:05",       // Local time format
		"2006-01-02T15:04:05Z07:00", // RFC3339 with timezone
		"2006-01-02 15:04:05",       // Fallback format
	}

	// First try parsing as local time
	if runTime, err := time.ParseInLocation(formats[0], runTimeStr, time.Local); err == nil {
		return runTime, nil
	}

	// Try other formats
	for _, format := range formats[1:] {
		if runTime, err := time.Parse(format, runTimeStr); err == nil {
			return runTime, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time format: %s", runTimeStr)
}

// Helper function to map domain scanner to protobuf scanner
func mapDomainToProto(scanner *domain.ScannerDomain) *pb.Scanner {
	if scanner == nil {
		return nil
	}

	pbScanner := &pb.Scanner{
		Id:                 strconv.FormatInt(scanner.ID, 10),
		Name:               scanner.Name,
		ScanType:           scanner.ScanType,
		Status:             scanner.Status,
		UserId:             scanner.UserID,
		CreatedAt:          scanner.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:          scanner.UpdatedAt.Format("2006-01-02 15:04:05"),
		Type:               scanner.Type,
		Target:             scanner.Target,
		Ip:                 scanner.IP,
		Subnet:             scanner.Subnet,
		StartIp:            scanner.StartIP,
		EndIp:              scanner.EndIP,
		Port:               scanner.Port,
		Username:           scanner.Username,
		Password:           scanner.Password,
		Domain:             scanner.Domain,
		AuthenticationType: scanner.AuthenticationType,
		Protocol:           scanner.Protocol,
	}

	// Add schedule if available
	if scanner.Schedule != nil {
		pbScanner.Schedule = &pb.Schedule{
			ScheduleType:   string(scanner.Schedule.ScheduleType),
			FrequencyValue: scanner.Schedule.FrequencyValue,
			FrequencyUnit:  scanner.Schedule.FrequencyUnit,
			Month:          scanner.Schedule.Month,
			Week:           scanner.Schedule.Week,
			Day:            scanner.Schedule.Day,
			Hour:           scanner.Schedule.Hour,
			Minute:         scanner.Schedule.Minute,
		}
	}

	return pbScanner
}
