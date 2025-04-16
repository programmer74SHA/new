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
	IP          string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type AssetFilters struct {
	Name      string
	Domain    string
	Hostname  string
	OSName    string
	OSVersion string
	Type      string
	IP        string
}

func AssetUUIDFromString(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
