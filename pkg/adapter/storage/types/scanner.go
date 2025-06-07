package types

import (
	"encoding/json"
	"net/http"
	"time"
)

// Scanner represents a scanner in the database
type Scanner struct {
	ID        int64      `gorm:"column:id;primaryKey;autoIncrement"`
	ScanType  string     `gorm:"column:scan_type"`
	Name      string     `gorm:"column:name;size:255;not null"`
	Status    bool       `gorm:"column:status;default:1"`
	CreatedAt time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt *time.Time `gorm:"column:updated_at;type:datetime"`
	UserID    *string    `gorm:"column:user_id;size:100"`
	DeletedAt *time.Time `gorm:"column:deleted_at;type:datetime"`

	NmapMetadatas     []NmapMetadata     `gorm:"foreignKey:ScannerID"`
	DomainMetadatas   []DomainMetadata   `gorm:"foreignKey:ScannerID"`
	VCenterMetadatas  []VcenterMetadata  `gorm:"foreignKey:ScannerID"`
	FirewallMetadatas []FirewallMetadata `gorm:"foreignKey:ScannerID"` // Add this line
	Schedules         []Schedule         `gorm:"foreignKey:ScannerID"`
	ScanJob           ScanJob            `gorm:"foreignKey:ScannerID"`
}

func (Scanner) TableName() string {
	return "scanners"
}

// ScannerFilter struct for filtering scanners
type ScannerFilter struct {
	Name     string `json:"name"`
	ScanType string `json:"type"`
	Status   *bool  `json:"status"`
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
	Password           string `gorm:"column:password;size:200;not null"`
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
	Password  string `gorm:"column:password;size:200;not null"`
}



type FortigateResponse struct {
	Results []json.RawMessage `json:"results"`
	Status  string            `json:"status"`
}

type Zone struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Interface   []ZoneInterface `json:"interface"`
}

type ZoneInterface struct {
	InterfaceName string `json:"interface-name"`
	Name          string `json:"name"` // Alternative field name
}

type Interface struct {
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Status        string   `json:"status"`
	Description   string   `json:"description"`
	MTU           int      `json:"mtu"`
	Speed         string   `json:"speed"`
	Duplex        string   `json:"duplex"`
	Type          string   `json:"type"`
	VDOM          string   `json:"vdom"`
	Mode          string   `json:"mode"`
	Role          string   `json:"role"`
	MacAddr       string   `json:"macaddr"`
	Allowaccess   []string `json:"allowaccess"`
	InterfaceName string   `json:"interface-name"`
	// Secondary IP addresses
	SecondaryIP []SecondaryIP `json:"secondaryip"`
	// Additional fields that FortiGate might return
	Alias                        string                   `json:"alias"`
	DeviceIdentification         string                   `json:"device-identification"`
	Dedicated                    string                   `json:"dedicated"`
	Trust                        string                   `json:"trust"`
	Algorithm                    string                   `json:"algorithm"`
	EstimatedUpstreamBandwidth   string                   `json:"estimated-upstream-bandwidth"`
	EstimatedDownstreamBandwidth string                   `json:"estimated-downstream-bandwidth"`
	MeasuredUpstreamBandwidth    string                   `json:"measured-upstream-bandwidth"`
	MeasuredDownstreamBandwidth  string                   `json:"measured-downstream-bandwidth"`
	BandwidthMeasureTime         int                      `json:"bandwidth-measure-time"`
	MonitorBandwidth             string                   `json:"monitor-bandwidth"`
	VLANID                       int                      `json:"vlanid"`
	ForwardDomain                int                      `json:"forwarddomain"`
	Remote                       string                   `json:"remote"`
	Member                       []map[string]interface{} `json:"member"`
	LaCP                         string                   `json:"lacp"`
	LacpMode                     string                   `json:"lacp-mode"`
	LacpHA                       string                   `json:"lacp-ha"`
	LacpHaSlave                  string                   `json:"lacp-ha-slave"`
	LacpHaMgmtVlan               int                      `json:"lacp-ha-mgmt-vlan"`
}

type SecondaryIP struct {
	ID          int      `json:"id"`
	IP          string   `json:"ip"`
	Allowaccess []string `json:"allowaccess"`
}

type Policy struct {
	PolicyID int               `json:"policyid"`
	Name     string            `json:"name"`
	SrcIntf  []PolicyInterface `json:"srcintf"`
	DstIntf  []PolicyInterface `json:"dstintf"`
	SrcAddr  []Address         `json:"srcaddr"`
	DstAddr  []Address         `json:"dstaddr"`
	Service  []Service         `json:"service"`
	Action   string            `json:"action"`
	Status   string            `json:"status"`
	Schedule string            `json:"schedule"`
}

type PolicyInterface struct {
	Name string `json:"name"`
}

type Address struct {
	Name   string `json:"name"`
	Subnet string `json:"subnet"`
	Type   string `json:"type"`
}

type Service struct {
	Name string `json:"name"`
}

type SystemInfo struct {
	Global map[string]interface{} `json:"global"`
	Status map[string]interface{} `json:"status"`
}

// FortiGate client
type FortigateClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

type FirewallMetadata struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	ScannerID int64  `gorm:"column:scanner_id;not null"`
	IP        string `gorm:"column:ip;size:50;not null"`
	Port      string `gorm:"column:port;size:50;not null"`
	ApiKey    string `gorm:"column:api_key;size:200;not null"` // Fixed column name
}


