package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanjobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
)

var (
	ErrScanJobNotFound    = errors.New("scan job not found")
	ErrInvalidScanJobUUID = errors.New("invalid scan job UUID")
)

// ScanJobService provides API operations for scan jobs
type ScanJobService struct {
	service scanjobPort.Service
}

// NewScanJobService creates a new ScanJobService
func NewScanJobService(srv scanjobPort.Service) *ScanJobService {
	return &ScanJobService{service: srv}
}

// GetJobs handles listing of scan jobs with filters, pagination, and sorting
func (s *ScanJobService) GetJobs(ctx context.Context, req *pb.GetJobsRequest) (*pb.GetJobsResponse, error) {
	// Parse filters
	filter := domain.ScanJobFilters{
		Name:   req.GetFilter().GetName(),
		Type:   req.GetFilter().GetType(),
		Status: req.GetFilter().GetStatus(),
	}

	// Parse time range
	if f := req.GetFilter().GetStartTimeFrom(); f != "" {
		if t, err := time.Parse(time.RFC3339, f); err == nil {
			filter.StartTimeFrom = &t
		}
	}

	if tStr := req.GetFilter().GetStartTimeTo(); tStr != "" {
		if t, err := time.Parse(time.RFC3339, tStr); err == nil {
			filter.StartTimeTo = &t
		}
	}

	// Pagination
	limit := int(req.GetLimit())
	offset := int(req.GetPage()) * limit

	// Sorting
	sorts := make([]domain.SortOption, len(req.GetSort()))
	for i, srt := range req.GetSort() {
		sorts[i] = domain.SortOption{Field: srt.GetField(), Order: srt.GetOrder()}
	}

	jobs, total, err := s.service.GetJobs(ctx, filter, limit, offset, sorts...)
	if err != nil {
		return nil, err
	}

	// Map to protobuf
	pbJobs := make([]*pb.ScanJob, 0, len(jobs))
	for _, job := range jobs {
		pbJob := &pb.ScanJob{
			Id:        job.ID.String(),
			Name:      job.Name,
			Type:      job.Type,
			Status:    job.Status,
			StartTime: job.StartTime.Format(time.RFC3339),
			EndTime:   "",
			Progress:  0,
			ScannerId: job.ScannerID,
		}
		if job.EndTime != nil {
			pbJob.EndTime = job.EndTime.Format(time.RFC3339)
		}
		if job.Progress != nil {
			pbJob.Progress = int32(*job.Progress)
		}

		pbJobs = append(pbJobs, pbJob)
	}

	return &pb.GetJobsResponse{Contents: pbJobs, Count: int32(total)}, nil
}

// GetJobByID handles retrieving a scan job by its ID
func (s *ScanJobService) GetJobByID(ctx context.Context, req *pb.GetJobByIDRequest) (*pb.GetJobByIDResponse, error) {
	// Parse UUID
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, ErrInvalidScanJobUUID
	}

	job, err := s.service.GetJobByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if job == nil {
		return nil, ErrScanJobNotFound
	}

	// Map to protobuf
	resp := &pb.GetJobByIDResponse{Job: &pb.ScanJob{
		Id:        job.ID.String(),
		Name:      job.Name,
		Type:      job.Type,
		Status:    job.Status,
		StartTime: job.StartTime.Format(time.RFC3339),
	}}

	// optional fields
	if job.EndTime != nil {
		resp.Job.EndTime = job.EndTime.Format(time.RFC3339)
	}

	if job.Progress != nil {
		resp.Job.Progress = int32(*job.Progress)
	}

	resp.Job.ScannerId = job.ScannerID

	// assets
	for _, as := range job.AssetScanJobs {
		asset := as.Asset
		pbAsset := &pb.Asset{Id: asset.ID.String(), Name: asset.Name, Domain: asset.Domain, Hostname: asset.Hostname, OsName: asset.OSName, OsVersion: asset.OSVersion, Type: asset.Type, Description: asset.Description, CreatedAt: asset.CreatedAt.Format(time.RFC3339), UpdatedAt: asset.UpdatedAt.Format(time.RFC3339), Risk: int32(asset.Risk)}
		resp.Job.AssetScanJobs = append(resp.Job.AssetScanJobs, &pb.AssetScanJob{Asset: pbAsset, DiscoveredAt: as.DiscoveredAt.Format(time.RFC3339)})
	}

	return resp, nil
}
