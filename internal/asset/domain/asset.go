package domain

import (
	"time"

	"github.com/google/uuid"
)

type AssetUUID = uuid.UUID

type Port struct {
	ID             string
	AssetID        string
	PortNumber     int
	Protocol       string
	State          string
	ServiceName    string
	ServiceVersion string
	Description    string
	DiscoveredAt   time.Time
}

type VMwareVM struct {
	VMID         string
	AssetID      string
	VMName       string
	Hypervisor   string
	CPUCount     int32
	MemoryMB     int32
	DiskSizeGB   int
	PowerState   string
	LastSyncedAt time.Time
}

type AssetIP struct {
	AssetID    string
	IP         string
	MACAddress string
}

type AssetDomain struct {
	ID          AssetUUID
	Name        string
	Domain      string
	Hostname    string
	OSName      string
	OSVersion   string
	Type        string
	Description string
	Risk        int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Ports       []Port
	VMwareVMs   []VMwareVM
	AssetIPs    []AssetIP
}

type SortOption struct {
	Field string
	Order string
}

type AssetFilters struct {
	Name      string
	Domain    string
	Hostname  string
	OSName    string
	OSVersion string
	Type      string
	IP        string // Keep for backward compatibility
}

func AssetUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
