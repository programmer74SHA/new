package storage

import (
	"context"
	"errors"

	scanJobDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/domain"
	scanJobPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanjob/port"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	typesMapper "gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types/mapper"
	"gorm.io/gorm"
)

type scanJobRepo struct {
	db *gorm.DB
}

func NewScanJobRepo(db *gorm.DB) scanJobPort.Repo {
	return &scanJobRepo{db: db}
}

func (r *scanJobRepo) Get(ctx context.Context, filter scanJobDomain.ScanJobFilters, limit, offset int, sortOptions ...scanJobDomain.SortOption) ([]scanJobDomain.ScanJob, int, error) {
	var jobs []types.ScanJob
	var total int64

	query := r.db.WithContext(ctx).Model(&types.ScanJob{})

	if filter.Name != "" {
		query = query.Where("name LIKE ?", "%"+filter.Name+"%")
	}
	if filter.Type != "" {
		query = query.Where("type = ?", filter.Type)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.StartTimeFrom != nil {
		query = query.Where("start_time >= ?", filter.StartTimeFrom)
	}
	if filter.StartTimeTo != nil {
		query = query.Where("start_time <= ?", filter.StartTimeTo)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	for _, sort := range sortOptions {
		dbField := sort.Field
		order := "ASC"
		if sort.Order == "desc" {
			order = "DESC"
		}
		query = query.Order(dbField + " " + order)
	}

	// Pagination
	query = query.Limit(limit).Offset(offset)

	if err := query.Find(&jobs).Error; err != nil {
		return nil, 0, err
	}

	// Map to domain
	result := make([]scanJobDomain.ScanJob, 0, len(jobs))
	for _, j := range jobs {
		d, err := typesMapper.ScanJobStorage2Domain(j)
		if err != nil {
			continue
		}
		result = append(result, *d)
	}

	return result, int(total), nil
}

func (r *scanJobRepo) GetByID(ctx context.Context, id scanJobDomain.ScanJobUUID) (*scanJobDomain.ScanJob, error) {
	var job types.ScanJob
	err := r.db.WithContext(ctx).Preload("AssetScanJobs.Asset").Where("id = ?", id).First(&job).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	d, err := typesMapper.ScanJobStorage2Domain(job)
	if err != nil {
		return nil, err
	}
	return d, nil
}
