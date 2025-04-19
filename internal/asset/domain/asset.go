package domain

import (
	"time"

	"github.com/google/uuid"
)

type AssetUUID = uuid.UUID

type AssetDomain struct {
	ID          AssetUUID
	Name        string
	Domain      string
	Hostname    string
	OSName      string
	OSVersion   string
	Type        string
	IPs         []string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AssetIP represents an IP address associated with an asset
type AssetIP struct {
	ID        uuid.UUID
	AssetID   AssetUUID
	IPAddress string
	CreatedAt time.Time
	UpdatedAt time.Time
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
