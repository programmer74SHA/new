package types

import (
	"time"
)

// Scanner represents a scanner in the database
type Scanner struct {
	ID        int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ScanType  string     `gorm:"column:scan_type"` // Changed from *int to string
	Name      string     `gorm:"column:name;size:255;not null"`
	Status    bool       `gorm:"column:status;default:1"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	UserID    *string    `gorm:"column:user_id;size:100"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`

	NmapMetadatas    []NmapMetadata    `gorm:"foreignKey:ScannerID"`
	DomainMetadatas  []DomainMetadata  `gorm:"foreignKey:ScannerID"`
	VCenterMetadatas []VcenterMetadata `gorm:"foreignKey:ScannerID"`
	Schedules        []Schedule        `gorm:"foreignKey:ScannerID"`
	ScanJob          ScanJob           `gorm:"foreignKey:ScannerID"`
}

func (Scanner) TableName() string {
	return "scanners"
}

// ScannerFilter struct for filtering scanners
type ScannerFilter struct {
	Name     string
	ScanType string
	Status   *bool
}

type NmapMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID int64  `gorm:"column:scanner_id;not null;uniqueIndex:nmap_metadatas_unique"`
	Type      string `gorm:"column:type;type:enum('Top Port','Default');not null"`
	Target    string `gorm:"column:target;type:enum('IP','Network','Range');not null"`

	Scanner     Scanner          `gorm:"foreignKey:ScannerID"`
	IPScan      *NmapIPScan      `gorm:"foreignKey:NmapMetadatasID"`
	NetworkScan *NmapNetworkScan `gorm:"foreignKey:NmapMetadatasID"`
	RangeScan   *NmapRangeScan   `gorm:"foreignKey:NmapMetadatasID"`
}

type NmapIPScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_ip_scan_unique"`
	IP              string `gorm:"column:ip;size:50;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

type NmapNetworkScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_network_scan_unique"`
	IP              string `gorm:"column:ip;size:50;not null"`
	Subnet          int64  `gorm:"column:subnet;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

type NmapRangeScan struct {
	ID              int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NmapMetadatasID int64  `gorm:"column:nmap_metadatas_id;not null;uniqueIndex:nmap_range_scan_unique"`
	StartIP         string `gorm:"column:start_ip;size:50;not null"`
	EndIP           string `gorm:"column:end_ip;size:50;not null"`

	NmapMetadata NmapMetadata `gorm:"foreignKey:NmapMetadatasID"`
}

type DomainMetadata struct {
	ID                 int64  `gorm:"column:id;primaryKey"`
	ScannerID          int64  `gorm:"column:scanner_id;not null"`
	IP                 string `gorm:"column:ip;size:50;not null"`
	Port               string `gorm:"column:port;size:50;not null"`
	Domain             string `gorm:"column:domain;size:50;not null"`
	Username           string `gorm:"column:username;size:50;not null"`
	Password           string `gorm:"column:password;size:50;not null"`
	AuthenticationType string `gorm:"column:authentication_type;size:50;not null"`
	Protocol           string `gorm:"column:protocol;size:50;not null"`

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}

type VcenterMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	ScannerID int64  `gorm:"column:scanner_id;not null"`
	IP        string `gorm:"column:ip;size:50;not null"`
	Port      string `gorm:"column:port;size:50;not null"`
	Username  string `gorm:"column:username;size:50;not null"`
	Password  string `gorm:"column:password;size:50;not null"`
}
