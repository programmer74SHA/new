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

// FirewallVendor represents firewall vendors lookup table
type FirewallVendor struct {
	ID         int64     `gorm:"column:id;primaryKey;autoIncrement"`
	VendorName string    `gorm:"column:vendor_name;size:100;not null;uniqueIndex"`
	VendorCode string    `gorm:"column:vendor_code;size:20;not null;uniqueIndex"`
	CreatedAt  time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
}

// Firewall represents main firewall devices table
type Firewall struct {
	ID              int64      `gorm:"column:id;primaryKey;autoIncrement"`
	VendorID        int64      `gorm:"column:vendor_id;not null"`
	Hostname        string     `gorm:"column:hostname;size:255;not null"`
	ManagementIP    string     `gorm:"column:management_ip;size:45;not null"`
	Model           *string    `gorm:"column:model;size:100"`
	FirmwareVersion *string    `gorm:"column:firmware_version;size:100"`
	SerialNumber    *string    `gorm:"column:serial_number;size:100"`
	SiteName        *string    `gorm:"column:site_name;size:255"`
	Location        *string    `gorm:"column:location;size:255"`
	IsHAEnabled     bool       `gorm:"column:is_ha_enabled;default:false"`
	HARole          string     `gorm:"column:ha_role;type:enum('active','passive','standalone');default:'standalone'"`
	LastSync        *time.Time `gorm:"column:last_sync;type:datetime"`
	SyncStatus      string     `gorm:"column:sync_status;type:enum('success','failed','pending');default:'pending'"`
	CreatedAt       time.Time  `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time  `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	Vendor             FirewallVendor      `gorm:"foreignKey:VendorID"`
	SecurityZones      []SecurityZone      `gorm:"foreignKey:FirewallID"`
	FirewallInterfaces []FirewallInterface `gorm:"foreignKey:FirewallID"`
	SecurityPolicies   []SecurityPolicy    `gorm:"foreignKey:FirewallID"`
	VLANs              []VLAN              `gorm:"foreignKey:FirewallID"`
	VendorConfigs      []VendorConfig      `gorm:"foreignKey:FirewallID"`
}

// SecurityZone represents security zones table
type SecurityZone struct {
	ID                    int64     `gorm:"column:id;primaryKey;autoIncrement"`
	FirewallID            int64     `gorm:"column:firewall_id;not null"`
	ZoneName              string    `gorm:"column:zone_name;size:100;not null"`
	ZoneType              string    `gorm:"column:zone_type;type:enum('security','virtual_router','context','vdom','vsys');default:'security'"`
	VendorZoneType        *string   `gorm:"column:vendor_zone_type;size:50"`
	Description           *string   `gorm:"column:description;type:text"`
	ZoneMode              string    `gorm:"column:zone_mode;type:enum('layer3','layer2','virtual-wire','tap');default:'layer3'"`
	IntrazoneAction       string    `gorm:"column:intrazone_action;type:enum('allow','deny');default:'allow'"`
	ZoneProtectionProfile *string   `gorm:"column:zone_protection_profile;size:100"`
	LogSetting            *string   `gorm:"column:log_setting;size:100"`
	CreatedAt             time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt             time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	Firewall   Firewall            `gorm:"foreignKey:FirewallID"`
	Interfaces []FirewallInterface `gorm:"foreignKey:ZoneID"`
}

// InterfaceType represents interface types lookup
type InterfaceType struct {
	ID          int64   `gorm:"column:id;primaryKey;autoIncrement"`
	TypeName    string  `gorm:"column:type_name;size:50;not null;uniqueIndex"`
	Description *string `gorm:"column:description;size:255"`
}

// FirewallInterface represents network interfaces table
type FirewallInterface struct {
	ID                   int64     `gorm:"column:id;primaryKey;autoIncrement"`
	FirewallID           int64     `gorm:"column:firewall_id;not null"`
	InterfaceName        string    `gorm:"column:interface_name;size:100;not null"`
	InterfaceTypeID      int64     `gorm:"column:interface_type_id;not null"`
	ZoneID               *int64    `gorm:"column:zone_id"`
	VirtualRouter        *string   `gorm:"column:virtual_router;size:100"`
	VirtualSystem        *string   `gorm:"column:virtual_system;size:100"`
	IPAddress            *string   `gorm:"column:ip_address;size:45"`
	Netmask              *string   `gorm:"column:netmask;size:45"`
	CIDRPrefix           *int      `gorm:"column:cidr_prefix"`
	IPv6Address          *string   `gorm:"column:ipv6_address;size:64"`
	IPv6Prefix           *int      `gorm:"column:ipv6_prefix"`
	Description          *string   `gorm:"column:description;type:text"`
	OperationalStatus    string    `gorm:"column:operational_status;type:enum('up','down','unknown');default:'unknown'"`
	AdminStatus          string    `gorm:"column:admin_status;type:enum('up','down');default:'up'"`
	MTU                  int       `gorm:"column:mtu;default:1500"`
	Speed                *string   `gorm:"column:speed;size:20"`
	Duplex               string    `gorm:"column:duplex;type:enum('full','half','auto')"`
	ParentInterfaceID    *int64    `gorm:"column:parent_interface_id"`
	VLANID               *int      `gorm:"column:vlan_id"`
	MACAddress           *string   `gorm:"column:mac_address;size:17"`
	VendorSpecificConfig *string   `gorm:"column:vendor_specific_config;type:json"`
	CreatedAt            time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt            time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	Firewall        Firewall            `gorm:"foreignKey:FirewallID"`
	InterfaceType   InterfaceType       `gorm:"foreignKey:InterfaceTypeID"`
	Zone            *SecurityZone       `gorm:"foreignKey:ZoneID"`
	ParentInterface *FirewallInterface  `gorm:"foreignKey:ParentInterfaceID"`
	ChildInterfaces []FirewallInterface `gorm:"foreignKey:ParentInterfaceID"`
	InterfaceIPs    []InterfaceIP       `gorm:"foreignKey:InterfaceID"`
	VLANInterface   *VLAN               `gorm:"foreignKey:VLANInterfaceID"`
}

// VLAN represents VLAN configurations
type VLAN struct {
	ID                   int64     `gorm:"column:id;primaryKey;autoIncrement"`
	FirewallID           int64     `gorm:"column:firewall_id;not null"`
	VLANID               int       `gorm:"column:vlan_id;not null"`
	VLANName             *string   `gorm:"column:vlan_name;size:100"`
	ParentInterfaceID    int64     `gorm:"column:parent_interface_id;not null"`
	VLANInterfaceID      *int64    `gorm:"column:vlan_interface_id"`
	Description          *string   `gorm:"column:description;type:text"`
	IsNative             bool      `gorm:"column:is_native;default:false"`
	VendorSpecificConfig *string   `gorm:"column:vendor_specific_config;type:json"`
	CreatedAt            time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt            time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	Firewall        Firewall           `gorm:"foreignKey:FirewallID"`
	ParentInterface FirewallInterface  `gorm:"foreignKey:ParentInterfaceID"`
	VLANInterface   *FirewallInterface `gorm:"foreignKey:VLANInterfaceID"`
}

// InterfaceIP represents multiple IP addresses per interface
type InterfaceIP struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	InterfaceID int64     `gorm:"column:interface_id;not null"`
	IPAddress   string    `gorm:"column:ip_address;size:45;not null"`
	Netmask     *string   `gorm:"column:netmask;size:45"`
	CIDRPrefix  *int      `gorm:"column:cidr_prefix"`
	IPVersion   string    `gorm:"column:ip_version;type:enum('ipv4','ipv6');default:'ipv4'"`
	IPType      string    `gorm:"column:ip_type;type:enum('primary','secondary','virtual','floating');default:'primary'"`
	CreatedAt   time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Interface FirewallInterface `gorm:"foreignKey:InterfaceID"`
}

// SecurityPolicy represents security policies
type SecurityPolicy struct {
	ID                   int64     `gorm:"column:id;primaryKey;autoIncrement"`
	FirewallID           int64     `gorm:"column:firewall_id;not null"`
	PolicyName           *string   `gorm:"column:policy_name;size:255"`
	PolicyID             *int      `gorm:"column:policy_id"`
	SrcZoneID            *int64    `gorm:"column:src_zone_id"`
	DstZoneID            *int64    `gorm:"column:dst_zone_id"`
	Action               string    `gorm:"column:action;type:enum('allow','deny','drop','reject','tunnel');default:'deny'"`
	PolicyType           string    `gorm:"column:policy_type;type:enum('security','nat','qos','decryption');default:'security'"`
	Status               string    `gorm:"column:status;type:enum('enabled','disabled');default:'enabled'"`
	RuleOrder            *int      `gorm:"column:rule_order"`
	VendorSpecificConfig *string   `gorm:"column:vendor_specific_config;type:json"`
	CreatedAt            time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`
	UpdatedAt            time.Time `gorm:"column:updated_at;type:datetime;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"`

	Firewall Firewall      `gorm:"foreignKey:FirewallID"`
	SrcZone  *SecurityZone `gorm:"foreignKey:SrcZoneID"`
	DstZone  *SecurityZone `gorm:"foreignKey:DstZoneID"`
}

// VendorConfig represents vendor-specific configurations
type VendorConfig struct {
	ID            int64     `gorm:"column:id;primaryKey;autoIncrement"`
	FirewallID    int64     `gorm:"column:firewall_id;not null"`
	ConfigType    string    `gorm:"column:config_type;size:100;not null"`
	ConfigSection *string   `gorm:"column:config_section;size:255"`
	RawConfig     *string   `gorm:"column:raw_config;type:longtext"`
	ParsedConfig  *string   `gorm:"column:parsed_config;type:json"`
	ConfigHash    *string   `gorm:"column:config_hash;size:64"`
	CreatedAt     time.Time `gorm:"column:created_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Firewall Firewall `gorm:"foreignKey:FirewallID"`
}

// FirewallScanJob represents the relationship between firewall and scan jobs
type FirewallScanJob struct {
	ID           int64     `gorm:"column:id;primaryKey;autoIncrement"`
	FirewallID   int64     `gorm:"column:firewall_id;not null"`
	ScanJobID    int64     `gorm:"column:scan_job_id;not null"`
	DiscoveredAt time.Time `gorm:"column:discovered_at;type:datetime;default:CURRENT_TIMESTAMP"`

	Firewall Firewall `gorm:"foreignKey:FirewallID"`
	ScanJob  ScanJob  `gorm:"foreignKey:ScanJobID"`
}
