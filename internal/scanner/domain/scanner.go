package domain

import (
	"time"
)

const (
	ScannerTypeNmap    = "NMAP"
	ScannerTypeVCenter = "VCENTER"
	ScannerTypeDomain  = "DOMAIN"
)

type ScannerDomain struct {
	ID                 int64
	Name               string
	ScanType           string
	Status             bool
	UserID             string
	Type               string
	Target             string
	IP                 string
	Subnet             int64
	StartIP            string
	EndIP              string
	Port               string
	Username           string
	Password           string
	Domain             string
	AuthenticationType string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          time.Time
	Schedule           *Schedule
}

type ScannerFilter struct {
	Name     string
	ScanType string
	Status   *bool
}

type NmapMetadata struct {
	ID        int64
	ScannerID int64
	Type      string
	Target    string
}

type NmapIpScan struct {
	ID              int64
	NmapMetadatasID int64
	IP              string
}

type NmapNetworkScan struct {
	ID              int64
	NmapMetadatasID int64
	IP              string
	Subnet          int64
}

type NmapRangeScan struct {
	ID              int64
	NmapMetadatasID int64
	StartIP         string
	EndIP           string
}

type VcenterMetadata struct {
	ID        int64
	ScannerID int64
	IP        string
	Port      string
	Username  string
	Password  string
}

type DomainMetadata struct {
	ID                 int64
	ScannerID          int64
	IP                 string
	Port               string
	Username           string
	Password           string
	Domain             string
	AuthenticationType string
}

type Schedule struct {
	ID             int64
	ScannerID      int64
	FrequencyValue int64
	FrequencyUnit  string
	Month          int64
	Week           int64
	Day            int64
	Hour           int64
	Minute         int64
	CreatedAt      time.Time
	UpdatedAt      *time.Time
}

type Pagination struct {
	Page      int
	Limit     int
	SortField string
	SortOrder string
}
