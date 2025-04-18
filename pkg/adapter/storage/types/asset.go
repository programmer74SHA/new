package types

import "time"

// AssetIP represents an IP address associated with an asset
type AssetIP struct {
	ID        string     `gorm:"column:id;size:50;primaryKey"`
	AssetID   string     `gorm:"column:asset_id;not null;index"`
	IPAddress string     `gorm:"column:ip_address;size:45;not null;uniqueIndex"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

type Asset struct {
	ID          string     `gorm:"column:id;size:50;primaryKey"`
	Name        *string    `gorm:"column:name;size:50"`
	Domain      *string    `gorm:"column:domain;size:50"`
	Hostname    string     `gorm:"column:hostname;size:255;not null"`
	MACAddress  *string    `gorm:"column:mac_address;size:17"`
	OSName      *string    `gorm:"column:os_name;size:100"`
	OSVersion   *string    `gorm:"column:os_version;size:50"`
	Description *string    `gorm:"column:description;size:500"`
	Type        string     `gorm:"column:asset_type;type:enum('Physical','Virtual','Unknown');not null"`
	CreatedAt   time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt   *time.Time `gorm:"column:updated_at;type:datetime"`
	DeletedAt   *time.Time `gorm:"column:deleted_at;type:datetime"`

	AssetIPs     []AssetIP     `gorm:"foreignKey:AssetID"` // Added relationship
	Ports        []Port        `gorm:"foreignKey:AssetID"`
	VMwareVMs    []VMwareVM    `gorm:"foreignKey:AssetID"`
	AssetScanJobs []AssetScanJob `gorm:"foreignKey:AssetID"`
}

type Port struct {
	ID             string    `gorm:"column:id;size:50;primaryKey"`
	AssetID        string    `gorm:"column:asset_id;not null"`
	PortNumber     int       `gorm:"column:port_number;not null"`
	Protocol       string    `gorm:"column:protocol;type:enum('TCP','UDP');not null"`
	State          string    `gorm:"column:state;type:enum('Open','Closed','Filtered');not null"`
	ServiceName    *string   `gorm:"column:service_name;size:100"`
	ServiceVersion *string   `gorm:"column:service_version;size:100"`
	DiscoveredAt   time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

type VMwareVM struct {
	VMID         string    `gorm:"column:vm_id;size:50;primaryKey"`
	AssetID      string    `gorm:"column:asset_id;not null"`
	VMName       string    `gorm:"column:vm_name;size:255;not null"`
	Hypervisor   string    `gorm:"column:hypervisor;size:100;not null"`
	CPUCount     int       `gorm:"column:cpu_count;not null"`
	MemoryMB     int       `gorm:"column:memory_mb;not null"`
	DiskSizeGB   int       `gorm:"column:disk_size_gb;not null"`
	PowerState   string    `gorm:"column:power_state;type:enum('On','Off','Suspended');not null"`
	LastSyncedAt time.Time `gorm:"column:last_synced_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset Asset `gorm:"foreignKey:AssetID"`
}

type AssetScanJob struct {
	ID           int64     `gorm:"column:id;primaryKey;autoIncrement"`
	AssetID      string    `gorm:"column:asset_id;not null;uniqueIndex:asset_job_unique"`
	ScanJobID    int64     `gorm:"column:scan_job_id;not null;uniqueIndex:asset_job_unique"`
	DiscoveredAt time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Asset   Asset   `gorm:"foreignKey:AssetID"`
	ScanJob ScanJob `gorm:"foreignKey:ScanJobID"`
}

type ScanJob struct {
	ID          int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string     `gorm:"column:name;size:50;not null"`
	Type        string     `gorm:"column:type;size:50;not null"`
	Status      string     `gorm:"column:status;type:enum('Pending','Running','Completed','Failed','Error','Cancelled');not null;default:Pending"` // Added 'Cancelled' to the enum
	EndDatetime *time.Time `gorm:"column:end_datetime;type:datetime"`
	StartTime   time.Time  `gorm:"column:start_time;type:datetime;default:CURRENT_TIMESTAMP"`
	EndTime     *time.Time `gorm:"column:end_time;type:datetime"`
	Progress    *int       `gorm:"column:progress"`
	ScannerID   int64      `gorm:"column:scanner_id;not null"`

	AssetScanJobs []AssetScanJob `gorm:"foreignKey:ScanJobID"`
}

type Schedule struct {
	ID             int64      `gorm:"column:id;primaryKey;autoIncrement"`
	FrequencyValue int64      `gorm:"column:frequency_value;not null;default:1"`
	FrequencyUnit  string     `gorm:"column:frequency_unit;size:50;not null"`
	Month          int64      `gorm:"column:month"`
	CreatedAt      time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt      *time.Time `gorm:"column:updated_at;type:datetime"`
	ScannerID      int64      `gorm:"column:scanner_id;not null"`
	Week           int64      `gorm:"column:week"`
	Day            int64      `gorm:"column:day"`
	Hour           int64      `gorm:"column:hour"`
	Minute         int64      `gorm:"column:minute"`
	NextRunTime    *time.Time `gorm:"column:next_run_time;type:datetime"` // Added field

	Scanner Scanner `gorm:"foreignKey:ScannerID"`
}