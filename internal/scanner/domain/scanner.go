package domain

import (
	"time"
)

const (
	ScannerTypeNmap     = "NMAP"
	ScannerTypeVCenter  = "VCENTER"
	ScannerTypeDomain   = "DOMAIN"
	ScannerTypeFirewall = "FIREWALL" // Added new firewall scanner type
)

// Authentication type constants
const (
	AuthTypeSimple    = "SIMPLE"    // Basic username/password authentication
	AuthTypeNTLM      = "NTLM"      // Windows NTLM authentication
	AuthTypeGSSAPI    = "GSSAPI"    // Kerberos authentication
	AuthTypeDIGESTMD5 = "DIGESTMD5" // DIGEST-MD5 authentication
)

// ScheduleType enum for different types of schedules
type ScheduleType string

const (
	ScheduleTypeRecurring   ScheduleType = "RECURRING"
	ScheduleTypeRunOnce     ScheduleType = "RUN_ONCE"
	ScheduleTypeImmediately ScheduleType = "IMMEDIATELY"
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
	Protocol           string
	RunTime            time.Time
	ApiKey             string 
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          time.Time
	Schedule           *Schedule
}

type ScannerFilter struct {
	Name     string `json:"name"`
	ScanType string `json:"type"`
	Status   *bool  `json:"status"`
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
	Protocol           string
}

type FirewallMetadata struct {
	ID        int64
	ScannerID int64
	IP        string
	Port      string
	APIKey    string
}

type Schedule struct {
	ID             int64
	ScannerID      int64
	ScheduleType   ScheduleType
	FrequencyValue int64
	FrequencyUnit  string
	RunTime        time.Time
	Month          int64
	Week           int64
	Day            int64
	Hour           int64
	Minute         int64
	CreatedAt      time.Time
	UpdatedAt      *time.Time
	NextRunTime    *time.Time // Added to support service layer calculated next run time
}

type Pagination struct {
	Page      int
	Limit     int
	SortField string
	SortOrder string
}

// DeleteParams encapsulates all possible parameters for scanner deletion operations
type DeleteParams struct {
	ID      *int64
	IDs     []int64
	Filters *ScannerFilter
	Exclude bool
}

// StatusUpdateParams encapsulates all possible parameters for scanner status updates
type StatusUpdateParams struct {
	IDs       []int64       // Specific scanner IDs to update (if empty, uses other criteria)
	Filter    ScannerFilter // Filter criteria for scanner selection
	Status    bool          // New status to set (true=enabled, false=disabled)
	Exclude   bool          // If true, exclude scanners matching filter; if false, include only matching scanners
	UpdateAll bool          // If true, update all scanners (may be combined with Filter)
}
