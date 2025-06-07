package domain

import "time"

// FirewallDevice represents a firewall device
type FirewallDevice struct {
	ID              int64               `json:"id"`
	VendorID        int64               `json:"vendor_id"`
	Hostname        string              `json:"hostname"`
	ManagementIP    string              `json:"management_ip"`
	Model           string              `json:"model,omitempty"`
	FirmwareVersion string              `json:"firmware_version,omitempty"`
	SerialNumber    string              `json:"serial_number,omitempty"`
	SiteName        string              `json:"site_name,omitempty"`
	Location        string              `json:"location,omitempty"`
	IsHAEnabled     bool                `json:"is_ha_enabled"`
	HARole          string              `json:"ha_role"`
	LastSync        *time.Time          `json:"last_sync,omitempty"`
	SyncStatus      string              `json:"sync_status"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	Vendor          FirewallVendor      `json:"vendor"`
	SecurityZones   []SecurityZone      `json:"security_zones,omitempty"`
	Interfaces      []FirewallInterface `json:"interfaces,omitempty"`
	Policies        []SecurityPolicy    `json:"policies,omitempty"`
	VLANs           []VLAN              `json:"vlans,omitempty"`
}

// FirewallVendor represents a firewall vendor
type FirewallVendor struct {
	ID         int64     `json:"id"`
	VendorName string    `json:"vendor_name"`
	VendorCode string    `json:"vendor_code"`
	CreatedAt  time.Time `json:"created_at"`
}

// SecurityZone represents a firewall security zone
type SecurityZone struct {
	ID                    int64               `json:"id"`
	FirewallID            int64               `json:"firewall_id"`
	ZoneName              string              `json:"zone_name"`
	ZoneType              string              `json:"zone_type"`
	VendorZoneType        string              `json:"vendor_zone_type,omitempty"`
	Description           string              `json:"description,omitempty"`
	ZoneMode              string              `json:"zone_mode"`
	IntrazoneAction       string              `json:"intrazone_action"`
	ZoneProtectionProfile string              `json:"zone_protection_profile,omitempty"`
	LogSetting            string              `json:"log_setting,omitempty"`
	CreatedAt             time.Time           `json:"created_at"`
	UpdatedAt             time.Time           `json:"updated_at"`
	Interfaces            []FirewallInterface `json:"interfaces,omitempty"`
}

// FirewallInterface represents a firewall network interface
type FirewallInterface struct {
	ID                   int64         `json:"id"`
	FirewallID           int64         `json:"firewall_id"`
	InterfaceName        string        `json:"interface_name"`
	InterfaceType        string        `json:"interface_type"`
	ZoneID               *int64        `json:"zone_id,omitempty"`
	ZoneName             string        `json:"zone_name,omitempty"`
	VirtualRouter        string        `json:"virtual_router,omitempty"`
	VirtualSystem        string        `json:"virtual_system,omitempty"`
	IPAddress            string        `json:"ip_address,omitempty"`
	Netmask              string        `json:"netmask,omitempty"`
	CIDRPrefix           *int          `json:"cidr_prefix,omitempty"`
	IPv6Address          string        `json:"ipv6_address,omitempty"`
	IPv6Prefix           *int          `json:"ipv6_prefix,omitempty"`
	Description          string        `json:"description,omitempty"`
	OperationalStatus    string        `json:"operational_status"`
	AdminStatus          string        `json:"admin_status"`
	MTU                  int           `json:"mtu"`
	Speed                string        `json:"speed,omitempty"`
	Duplex               string        `json:"duplex"`
	ParentInterfaceID    *int64        `json:"parent_interface_id,omitempty"`
	VLANID               *int          `json:"vlan_id,omitempty"`
	MACAddress           string        `json:"mac_address,omitempty"`
	VendorSpecificConfig string        `json:"vendor_specific_config,omitempty"`
	CreatedAt            time.Time     `json:"created_at"`
	UpdatedAt            time.Time     `json:"updated_at"`
	InterfaceIPs         []InterfaceIP `json:"interface_ips,omitempty"`
}

// InterfaceIP represents an IP address assigned to an interface
type InterfaceIP struct {
	ID          int64     `json:"id"`
	InterfaceID int64     `json:"interface_id"`
	IPAddress   string    `json:"ip_address"`
	Netmask     string    `json:"netmask,omitempty"`
	CIDRPrefix  *int      `json:"cidr_prefix,omitempty"`
	IPVersion   string    `json:"ip_version"`
	IPType      string    `json:"ip_type"`
	CreatedAt   time.Time `json:"created_at"`
}

// SecurityPolicy represents a firewall security policy
type SecurityPolicy struct {
	ID                   int64     `json:"id"`
	FirewallID           int64     `json:"firewall_id"`
	PolicyName           string    `json:"policy_name,omitempty"`
	PolicyID             *int      `json:"policy_id,omitempty"`
	SrcZoneID            *int64    `json:"src_zone_id,omitempty"`
	DstZoneID            *int64    `json:"dst_zone_id,omitempty"`
	SrcZoneName          string    `json:"src_zone_name,omitempty"`
	DstZoneName          string    `json:"dst_zone_name,omitempty"`
	Action               string    `json:"action"`
	PolicyType           string    `json:"policy_type"`
	Status               string    `json:"status"`
	RuleOrder            *int      `json:"rule_order,omitempty"`
	VendorSpecificConfig string    `json:"vendor_specific_config,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// VLAN represents a VLAN configuration
type VLAN struct {
	ID                   int64              `json:"id"`
	FirewallID           int64              `json:"firewall_id"`
	VLANID               int                `json:"vlan_id"`
	VLANName             string             `json:"vlan_name,omitempty"`
	ParentInterfaceID    int64              `json:"parent_interface_id"`
	ParentInterfaceName  string             `json:"parent_interface_name,omitempty"`
	VLANInterfaceID      *int64             `json:"vlan_interface_id,omitempty"`
	VLANInterfaceName    string             `json:"vlan_interface_name,omitempty"`
	Description          string             `json:"description,omitempty"`
	IsNative             bool               `json:"is_native"`
	VendorSpecificConfig string             `json:"vendor_specific_config,omitempty"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
	ParentInterface      *FirewallInterface `json:"parent_interface,omitempty"`
	VLANInterface        *FirewallInterface `json:"vlan_interface,omitempty"`
}

// VendorConfig represents vendor-specific configuration
type VendorConfig struct {
	ID            int64     `json:"id"`
	FirewallID    int64     `json:"firewall_id"`
	ConfigType    string    `json:"config_type"`
	ConfigSection string    `json:"config_section,omitempty"`
	RawConfig     string    `json:"raw_config,omitempty"`
	ParsedConfig  string    `json:"parsed_config,omitempty"`
	ConfigHash    string    `json:"config_hash,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// FirewallFilters represents filters for firewall queries
type FirewallFilters struct {
	VendorCode   string `json:"vendor_code,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	ManagementIP string `json:"management_ip,omitempty"`
	SiteName     string `json:"site_name,omitempty"`
	Location     string `json:"location,omitempty"`
	SyncStatus   string `json:"sync_status,omitempty"`
}

// FirewallInterfaceFilters represents filters for interface queries
type FirewallInterfaceFilters struct {
	FirewallID        int64  `json:"firewall_id,omitempty"`
	InterfaceName     string `json:"interface_name,omitempty"`
	InterfaceType     string `json:"interface_type,omitempty"`
	ZoneName          string `json:"zone_name,omitempty"`
	IPAddress         string `json:"ip_address,omitempty"`
	OperationalStatus string `json:"operational_status,omitempty"`
	AdminStatus       string `json:"admin_status,omitempty"`
}

// SecurityPolicyFilters represents filters for security policy queries
type SecurityPolicyFilters struct {
	FirewallID  int64  `json:"firewall_id,omitempty"`
	PolicyName  string `json:"policy_name,omitempty"`
	SrcZoneName string `json:"src_zone_name,omitempty"`
	DstZoneName string `json:"dst_zone_name,omitempty"`
	Action      string `json:"action,omitempty"`
	PolicyType  string `json:"policy_type,omitempty"`
	Status      string `json:"status,omitempty"`
}

// FirewallSummary represents firewall summary information
type FirewallSummary struct {
	ID              int64      `json:"id"`
	Hostname        string     `json:"hostname"`
	ManagementIP    string     `json:"management_ip"`
	VendorName      string     `json:"vendor_name"`
	Model           string     `json:"model,omitempty"`
	FirmwareVersion string     `json:"firmware_version,omitempty"`
	SiteName        string     `json:"site_name,omitempty"`
	Location        string     `json:"location,omitempty"`
	LastSync        *time.Time `json:"last_sync,omitempty"`
	SyncStatus      string     `json:"sync_status"`
	InterfaceCount  int        `json:"interface_count"`
	ZoneCount       int        `json:"zone_count"`
	PolicyCount     int        `json:"policy_count"`
	VLANCount       int        `json:"vlan_count"`
}

// FirewallStatistics represents firewall statistics
type FirewallStatistics struct {
	TotalFirewalls        int                   `json:"total_firewalls"`
	FirewallsByVendor     map[string]int        `json:"firewalls_by_vendor"`
	FirewallsBySyncStatus map[string]int        `json:"firewalls_by_sync_status"`
	TotalInterfaces       int                   `json:"total_interfaces"`
	InterfacesByStatus    map[string]int        `json:"interfaces_by_status"`
	TotalZones            int                   `json:"total_zones"`
	TotalPolicies         int                   `json:"total_policies"`
	PoliciesByAction      map[string]int        `json:"policies_by_action"`
	TotalVLANs            int                   `json:"total_vlans"`
	LastSyncTimes         map[string]*time.Time `json:"last_sync_times"`
}


// Pagination represents pagination options
type Pagination struct {
	Page   int `json:"page"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// FirewallExportData represents firewall data for export
type FirewallExportData struct {
	Firewalls  []map[string]interface{} `json:"firewalls"`
	Zones      []map[string]interface{} `json:"zones"`
	Interfaces []map[string]interface{} `json:"interfaces"`
	Policies   []map[string]interface{} `json:"policies"`
	VLANs      []map[string]interface{} `json:"vlans"`
}

// ExportFormat represents the export format type
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatXLSX ExportFormat = "xlsx"
)
