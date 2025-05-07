package scanjob

import (
	"context"

	domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
)

// service implements scanJobPort.Service
type service struct {
	repo scanJobPort.Repo
}

// NewScanJobService creates a new scan job service
func NewScanJobService(repo scanJobPort.Repo) scanJobPort.Service {
	return &service{repo: repo}
}

// GetJobs retrieves scan jobs based on filter, pagination, and sorting
func (s *service) GetJobs(ctx context.Context, filter domain.ScanJobFilters, limit, offset int, sortOptions ...domain.SortOption) ([]domain.ScanJob, int, error) {
	return s.repo.Get(ctx, filter, limit, offset, sortOptions...)
}

// GetJobByID retrieves a single scan job by its ID
func (s *service) GetJobByID(ctx context.Context, id domain.ScanJobUUID) (*domain.ScanJob, error) {
	return s.repo.GetByID(ctx, id)
}
