package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
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
	service          scannerPort.Service
	schedulerService schedulerPort.Service
}

func NewScannerService(srv scannerPort.Service) *ScannerService {
	return &ScannerService{
		service: srv,
	}
}

// SetSchedulerService sets the scheduler service reference
func (s *ScannerService) SetSchedulerService(schedulerSrv schedulerPort.Service) {
	s.schedulerService = schedulerSrv
}

// CreateScanner creates a new scanner
func (s *ScannerService) CreateScanner(ctx context.Context, req *pb.CreateScannerRequest) (*pb.CreateScannerResponse, error) {
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
		Domain:             req.GetDomain(),
		AuthenticationType: req.GetAuthenticationType(),
	}

	// Add schedule if provided
	if req.GetSchedule() != nil {
		scanner.Schedule = &domain.Schedule{
			FrequencyValue: req.GetSchedule().GetFrequencyValue(),
			FrequencyUnit:  req.GetSchedule().GetFrequencyUnit(),
			Month:          req.GetSchedule().GetMonth(),
			Week:           req.GetSchedule().GetWeek(),
			Day:            req.GetSchedule().GetDay(),
			Hour:           req.GetSchedule().GetHour(),
			Minute:         req.GetSchedule().GetMinute(),
		}
	}

	// Call internal service
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
	id, err := strconv.ParseInt(req.GetId(), 10, 64)
	if err != nil {
		return &pb.UpdateScannerResponse{
			Success:      false,
			ErrorMessage: "Invalid scanner ID",
		}, ErrInvalidScannerInput
	}

	// Create scanner domain object
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
		Domain:             req.GetDomain(),
		AuthenticationType: req.GetAuthenticationType(),
	}

	// Add schedule if frequency info is provided
	if req.GetFrequencyValue() > 0 && req.GetFrequencyUnit() != "" {
		scanner.Schedule = &domain.Schedule{
			FrequencyValue: req.GetFrequencyValue(),
			FrequencyUnit:  req.GetFrequencyUnit(),
			Month:          req.GetMonth(),
			Week:           req.GetWeek(),
			Day:            req.GetDay(),
			Hour:           req.GetHour(),
			Minute:         req.GetMinute(),
		}
	}

	// Update scanner using internal service
	if err := s.service.UpdateScanner(ctx, scanner); err != nil {
		return &pb.UpdateScannerResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Map domain model to response
	pbScanner := &pb.Scanner{
		Id:       req.GetId(),
		Name:     scanner.Name,
		ScanType: scanner.ScanType,
		Status:   scanner.Status,
	}

	return &pb.UpdateScannerResponse{
		Success: true,
		Scanner: pbScanner,
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
	// Convert string IDs to int64 slice
	var ids []int64
	for _, idStr := range req.GetIds() {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	// Call internal service to batch delete
	deletedCount, err := s.service.DeleteScanners(ctx, ids)
	if err != nil {
		return &pb.DeleteScannersResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.DeleteScannersResponse{
		Success:      true,
		DeletedCount: int32(deletedCount),
	}, nil
}

// Updated ListScanners function in api/service/scanner.go
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
		// Don't set filter.Status, which means no status filtering
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
	var pbScanners []*pb.Scanner
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

func (s *ScannerService) BatchUpdateScannersEnabled(ctx context.Context, req *pb.BatchUpdateScannersEnabledRequest) (*pb.BatchUpdateScannersEnabledResponse, error) {
	// Convert string IDs to int64 slice
	var ids []int64
	for _, idStr := range req.GetIds() {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	// Call internal service to batch update
	updatedCount, err := s.service.BatchUpdateScannersEnabled(ctx, ids, req.GetStatus())
	if err != nil {
		return &pb.BatchUpdateScannersEnabledResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	return &pb.BatchUpdateScannersEnabledResponse{
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

// RunScanNow immediately executes a scan for the specified scanner
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

	// Check if scheduler service is set
	if s.schedulerService == nil {
		log.Printf("Service: Scheduler service not available")
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Scheduler service not available",
		}, errors.New("scheduler service not available")
	}

	// Create a scan job record
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

	// Use the scheduler service to create a scan job
	jobID, err := s.schedulerService.CreateScanJob(ctx, scanJob)
	if err != nil {
		log.Printf("Service: Error creating scan job: %v", err)
		return &pb.RunScanNowResponse{
			Success:      false,
			ErrorMessage: "Failed to create scan job: " + err.Error(),
		}, err
	}

	// Execute the scan in a goroutine
	go func() {
		// Create a new context for the background operation
		bgCtx := context.Background()

		// Update job status to show scan is starting
		err := s.schedulerService.UpdateScanJobStatus(bgCtx, jobID, schedulerDomain.ScheduleStatusRunning, 10)
		if err != nil {
			log.Printf("Service: Failed to update scan job status: %v", err)
		}

		// Execute the appropriate scan based on scanner type
		var scanErr error
		if scanner.ScanType == scannerDomain.ScannerTypeNmap {
			// We need to find a way to access the NmapScanner
			// This would require adding a method to the scheduler service
			scanErr = s.schedulerService.ExecuteManualScan(bgCtx, *scanner, jobID)
		} else {
			scanErr = fmt.Errorf("unsupported scanner type: %s", scanner.ScanType)
		}

		// Update job status based on scan result
		if scanErr != nil {
			log.Printf("Service: Error executing scan: %v", scanErr)
			err := s.schedulerService.CompleteScanJob(bgCtx, jobID, schedulerDomain.ScheduleStatusFailed)
			if err != nil {
				log.Printf("Service: Failed to update job status to failed: %v", err)
			}
		} else {
			err := s.schedulerService.CompleteScanJob(bgCtx, jobID, schedulerDomain.ScheduleStatusComplete)
			if err != nil {
				log.Printf("Service: Failed to update job status to complete: %v", err)
			}
		}

		log.Printf("Service: Manual scan job ID %d completed with status: %v", jobID, scanErr == nil)
	}()

	return &pb.RunScanNowResponse{
		Success: true,
		JobId:   jobID,
	}, nil
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
		Status:             scanner.Status, // This line is crucial - ensure it's always set
		UserId:             scanner.UserID,
		CreatedAt:          scanner.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:          scanner.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
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
	}

	// // Add schedule if available
	// if scanner.Schedule != nil {
	// 	pbScanner.Schedule = &pb.Schedule{
	// 		FrequencyValue: scanner.Schedule.FrequencyValue,
	// 		FrequencyUnit:  scanner.Schedule.FrequencyUnit,
	// 		Month:          scanner.Schedule.Month,
	// 		Week:           scanner.Schedule.Week,
	// 		Day:            scanner.Schedule.Day,
	// 		Hour:           scanner.Schedule.Hour,
	// 		Minute:         scanner.Schedule.Minute,
	// 	}
	// }

	return pbScanner
}
