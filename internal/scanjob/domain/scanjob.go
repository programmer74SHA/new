package domain

import (
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
)

// ScanJobUUID represents the unique identifier for a scan job
type ScanJobUUID = uuid.UUID

// AssetScanJob links an asset with its discovery details in a scan job
type AssetScanJob struct {
	Asset        assetDomain.AssetDomain
	DiscoveredAt time.Time
}

// ScanJob represents a scanning job and its related metadata
type ScanJob struct {
	ID            ScanJobUUID
	Name          string
	Type          string
	Status        string
	StartTime     time.Time
	EndTime       *time.Time
	Progress      *int
	ScannerID     int64
	AssetScanJobs []AssetScanJob
}

// ScanJobFilters defines supported filters for querying scan jobs
type ScanJobFilters struct {
	Name          string
	Type          string
	Status        string
	StartTimeFrom *time.Time
	StartTimeTo   *time.Time
}

// SortOption defines sorting options for scan job queries
type SortOption struct {
	Field string
	Order string
}
