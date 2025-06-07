package domain

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

var (
	ErrIPAlreadyExists       = errors.New("IP address already exists")
	ErrHostnameAlreadyExists = errors.New("Hostname already exists")
)

type AssetUUID = uuid.UUID

type Port struct {
	ID             string    `json:"id"`
	AssetID        string    `json:"asset_id"`
	PortNumber     int       `json:"port_number"`
	Protocol       string    `json:"protocol"`
	State          string    `json:"state"`
	ServiceName    string    `json:"service_name"`
	ServiceVersion string    `json:"service_version"`
	Description    string    `json:"description"`
	DiscoveredAt   time.Time `json:"discovered_at"`
}

type VMwareVM struct {
	VMID         string    `json:"vm_id"`
	AssetID      string    `json:"asset_id"`
	VMName       string    `json:"vm_name"`
	Hypervisor   string    `json:"hypervisor"`
	CPUCount     int32     `json:"cpu_count"`
	MemoryMB     int32     `json:"memory_mb"`
	DiskSizeGB   int       `json:"disk_size_gb"`
	PowerState   string    `json:"power_state"`
	LastSyncedAt time.Time `json:"last_synced_at"`
}

type AssetIP struct {
	AssetID    string `json:"asset_id"`
	IP         string `json:"ip"`
	MACAddress string `json:"mac_address"`
}

type AssetDomain struct {
	ID               AssetUUID                    `json:"id"`
	Name             string                       `json:"name"`
	Domain           string                       `json:"domain"`
	Hostname         string                       `json:"hostname"`
	OSName           string                       `json:"os_name"`
	OSVersion        string                       `json:"os_version"`
	Type             string                       `json:"type"`
	Description      string                       `json:"description"`
	Risk             int                          `json:"risk"`
	LoggingCompleted bool                         `json:"logging_completed"`
	AssetValue       int                          `json:"asset_value"`
	CreatedAt        time.Time                    `json:"created_at"`
	UpdatedAt        time.Time                    `json:"updated_at"`
	Ports            []Port                       `json:"-"`
	VMwareVMs        []VMwareVM                   `json:"-"`
	AssetIPs         []AssetIP                    `json:"-"`
	Scanner          *scannerDomain.ScannerDomain `json:"-"`
}

type SortOption struct {
	Field string
	Order string
}

type AssetFilters struct {
	Name        string
	Domain      string
	Hostname    string
	OSName      string
	OSVersion   string
	Type        string
	IP          string
	ScannerType string
	Network     string
}

func AssetUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// ToMap converts any struct to map[string]interface{} using JSON marshaling/unmarshaling
func ToMap(obj interface{}) (map[string]interface{}, error) {
	// Marshal to JSON
	jsonData, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	// Unmarshal to map
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
