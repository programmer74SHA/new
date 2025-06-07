package mapper

import (
	"github.com/google/uuid"
	Domain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	ScannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
)

func AssetDomain2Storage(asset Domain.AssetDomain) (*types.Asset, []*types.AssetIP) {
	assetStorage := &types.Asset{
		ID:        asset.ID.String(),
		Hostname:  asset.Hostname,
		Type:      asset.Type,
		CreatedAt: asset.CreatedAt,
	}

	// Handle non-zero values for pointers
	if asset.Name != "" {
		assetStorage.Name = &asset.Name
	}
	if asset.Domain != "" {
		assetStorage.Domain = &asset.Domain
	}
	if asset.OSName != "" {
		assetStorage.OSName = &asset.OSName
	}
	if asset.OSVersion != "" {
		assetStorage.OSVersion = &asset.OSVersion
	}
	if asset.Description != "" {
		assetStorage.Description = &asset.Description
	}

	assetStorage.Risk = &asset.Risk
	assetStorage.LoggingCompleted = &asset.LoggingCompleted
	assetStorage.AssetValue = &asset.AssetValue

	// Set UpdatedAt if not zero
	if !asset.UpdatedAt.IsZero() {
		assetStorage.UpdatedAt = &asset.UpdatedAt
	}

	// Create AssetIP objects for each IP
	assetIPs := make([]*types.AssetIP, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		mac := ip.MACAddress
		if mac == "" {
			mac = "Unknown"
		}
		assetIPs = append(assetIPs, &types.AssetIP{
			ID:         uuid.New().String(),
			AssetID:    asset.ID.String(),
			IPAddress:  ip.IP,
			MACAddress: mac,
			CreatedAt:  asset.CreatedAt,
			UpdatedAt:  assetStorage.UpdatedAt,
		})
	}

	return assetStorage, assetIPs
}

func AssetStorage2Domain(asset types.Asset) (*Domain.AssetDomain, error) {
	uid, err := Domain.AssetUUIDFromString(asset.ID)
	if err != nil {
		return nil, err
	}

	ports := make([]Domain.Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		var serviceName, serviceVersion, description string
		if port.ServiceName != nil {
			serviceName = *port.ServiceName
		}
		if port.ServiceVersion != nil {
			serviceVersion = *port.ServiceVersion
		}
		if port.Description != nil {
			description = *port.Description
		}

		ports = append(ports, Domain.Port{
			ID:             port.ID,
			AssetID:        port.AssetID,
			PortNumber:     port.PortNumber,
			Protocol:       port.Protocol,
			State:          port.State,
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
			Description:    description,
			DiscoveredAt:   port.DiscoveredAt,
		})
	}

	vms := make([]Domain.VMwareVM, 0, len(asset.VMwareVMs))
	for _, vm := range asset.VMwareVMs {
		vms = append(vms, Domain.VMwareVM{
			VMID:         vm.VMID,
			AssetID:      vm.AssetID,
			VMName:       vm.VMName,
			Hypervisor:   vm.Hypervisor,
			CPUCount:     int32(vm.CPUCount),
			MemoryMB:     int32(vm.MemoryMB),
			DiskSizeGB:   vm.DiskSizeGB,
			PowerState:   vm.PowerState,
			LastSyncedAt: vm.LastSyncedAt,
		})
	}

	ips := make([]Domain.AssetIP, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		ips = append(ips, Domain.AssetIP{
			AssetID:    ip.AssetID,
			IP:         ip.IPAddress,
			MACAddress: ip.MACAddress,
		})
	}

	// Handle null pointers safely
	var name, domainStr, osName, osVersion, description string
	var risk, assetValue int
	var loggingCompleted bool
	if asset.Name != nil {
		name = *asset.Name
	}
	if asset.Domain != nil {
		domainStr = *asset.Domain
	}
	if asset.OSName != nil {
		osName = *asset.OSName
	}
	if asset.OSVersion != nil {
		osVersion = *asset.OSVersion
	}
	if asset.Description != nil {
		description = *asset.Description
	}
	if asset.Risk != nil {
		risk = *asset.Risk
	}
	if asset.LoggingCompleted != nil {
		loggingCompleted = *asset.LoggingCompleted
	}
	if asset.AssetValue != nil {
		assetValue = *asset.AssetValue
	}

	updatedAt := asset.CreatedAt
	if asset.UpdatedAt != nil {
		updatedAt = *asset.UpdatedAt
	}

	return &Domain.AssetDomain{
		ID:               uid,
		Name:             name,
		Domain:           domainStr,
		Hostname:         asset.Hostname,
		OSName:           osName,
		OSVersion:        osVersion,
		Type:             asset.Type,
		Description:      description,
		Risk:             risk,
		LoggingCompleted: loggingCompleted,
		AssetValue:       assetValue,
		CreatedAt:        asset.CreatedAt,
		UpdatedAt:        updatedAt,
		Ports:            ports,
		VMwareVMs:        vms,
		AssetIPs:         ips,
	}, nil
}

func AssetStorage2DomainWithScannerType(asset types.Asset, scannerType string) (*Domain.AssetDomain, error) {
	assetDomain, err := AssetStorage2Domain(asset)
	if err != nil {
		return nil, err
	}

	scannerObj := &ScannerDomain.ScannerDomain{
		Type: scannerType,
	}

	assetDomain.Scanner = scannerObj
	return assetDomain, nil
}

// PortDomain2Storage maps domain.Port to storage.Port
func PortDomain2Storage(port Domain.Port) *types.Port {
	portStorage := &types.Port{
		ID:           port.ID,
		AssetID:      port.AssetID,
		PortNumber:   port.PortNumber,
		Protocol:     port.Protocol,
		State:        port.State,
		DiscoveredAt: port.DiscoveredAt,
	}

	// Only set pointer fields if they have values
	if port.ServiceName != "" {
		portStorage.ServiceName = &port.ServiceName
	}
	if port.ServiceVersion != "" {
		portStorage.ServiceVersion = &port.ServiceVersion
	}
	if port.Description != "" {
		portStorage.Description = &port.Description
	}

	return portStorage
}

// AssetIPDomain2Storage maps domain.AssetIP to storage.AssetIP
func AssetIPDomain2Storage(ip Domain.AssetIP) *types.AssetIP {
	return &types.AssetIP{
		ID:         uuid.New().String(),
		AssetID:    ip.AssetID,
		IPAddress:  ip.IP,
		MACAddress: ip.MACAddress,
	}
}
