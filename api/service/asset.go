package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
)

var (
	ErrAssetNotFound         = asset.ErrAssetNotFound
	ErrInvalidAssetUUID      = asset.ErrInvalidAssetUUID
	ErrAssetCreateFailed     = asset.ErrAssetCreateFailed
	ErrAssetDeleteFailed     = asset.ErrAssetDeleteFailed
	ErrIPAlreadyExists       = asset.ErrIPAlreadyExists
	ErrHostnameAlreadyExists = asset.ErrHostnameAlreadyExists
)

type AssetService struct {
	service assetPort.Service
}

func NewAssetService(srv assetPort.Service) *AssetService {
	return &AssetService{
		service: srv,
	}
}

func (s *AssetService) GetAsset(ctx context.Context, req *pb.GetAssetByIDRequest) (*pb.GetAssetResponse, error) {
	assetUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, ErrInvalidAssetUUID
	}

	asset, err := s.service.GetByID(ctx, assetUUID)
	if err != nil {
		if errors.Is(err, ErrAssetNotFound) {
			return &pb.GetAssetResponse{}, nil
		}
		return nil, err
	}

	return &pb.GetAssetResponse{
		Asset: domainToPbAsset(*asset),
	}, nil
}

func (s *AssetService) GetAssets(ctx context.Context, req *pb.GetAssetsRequest) (*pb.GetAssetsResponse, error) {
	filter := domain.AssetFilters{
		Name:        req.GetFilter().GetName(),
		Domain:      req.GetFilter().GetDomain(),
		Hostname:    req.GetFilter().GetHostname(),
		OSName:      req.GetFilter().GetOsName(),
		OSVersion:   req.GetFilter().GetOsVersion(),
		Type:        req.GetFilter().GetType(),
		IP:          req.GetFilter().GetIp(),
		ScannerType: req.GetFilter().GetScannerType(),
		Network:     req.GetFilter().GetNetwork(),
	}

	limit := int(req.GetLimit())
	// Convert page to offset
	offset := int(req.GetPage()) * limit

	if limit < 0 {
		limit = 0
	}

	if offset < 0 {
		offset = 0
	}

	// Extract sort options
	sortFields := make([]domain.SortOption, 0, len(req.GetSort()))
	for _, sort := range req.GetSort() {
		sortFields = append(sortFields, domain.SortOption{
			Field: sort.GetField(),
			Order: sort.GetOrder(),
		})
	}

	assets, total, err := s.service.Get(ctx, filter, limit, offset, sortFields...)
	if err != nil {
		return nil, err
	}

	pbAssets := make([]*pb.Asset, 0, len(assets))
	for _, asset := range assets {
		pbAssets = append(pbAssets, domainToPbAsset(asset))
	}

	return &pb.GetAssetsResponse{
		Contents: pbAssets,
		Count:    int32(total),
	}, nil
}

// CreateAsset handles creation of a new asset
func (s *AssetService) CreateAsset(ctx context.Context, req *pb.CreateAssetRequest) (*pb.CreateAssetResponse, error) {
	id := uuid.New()
	now := time.Now()

	// Prepare ports
	ports := make([]domain.Port, 0, len(req.GetPorts()))
	for _, p := range req.GetPorts() {
		ports = append(ports, domain.Port{
			ID:             uuid.New().String(),
			AssetID:        id.String(),
			PortNumber:     int(p.GetPortNumber()),
			Protocol:       p.GetProtocol(),
			State:          p.GetState(),
			ServiceName:    p.GetServiceName(),
			ServiceVersion: p.GetServiceVersion(),
			Description:    p.GetDescription(),
			DiscoveredAt:   now,
		})
	}

	// Prepare asset IPs
	ips := make([]domain.AssetIP, 0, len(req.GetAssetIps()))
	for _, ip := range req.GetAssetIps() {
		ips = append(ips, domain.AssetIP{
			AssetID:    id.String(),
			IP:         ip.GetIp(),
			MACAddress: ip.GetMacAddress(),
		})
	}

	assetDomain := domain.AssetDomain{
		ID:               id,
		Name:             req.GetName(),
		Domain:           req.GetDomain(),
		Hostname:         req.GetHostname(),
		OSName:           req.GetOsName(),
		OSVersion:        req.GetOsVersion(),
		Type:             req.GetType(),
		Description:      req.GetDescription(),
		Risk:             int(req.GetRisk()),
		LoggingCompleted: req.GetLoggingCompleted(),
		AssetValue:       int(req.GetAssetValue()),
		CreatedAt:        now,
		Ports:            ports,
		AssetIPs:         ips,
	}

	aid, err := s.service.CreateAsset(ctx, assetDomain)
	if err != nil {
		return nil, err
	}

	return &pb.CreateAssetResponse{Id: aid.String()}, nil
}

// UpdateAsset handles updating an existing asset
func (s *AssetService) UpdateAsset(ctx context.Context, req *pb.UpdateAssetRequest) (*pb.UpdateAssetResponse, error) {
	assetUUID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, ErrInvalidAssetUUID
	}

	now := time.Now()

	// Prepare ports
	ports := make([]domain.Port, 0, len(req.GetPorts()))
	for _, p := range req.GetPorts() {
		dt, _ := time.Parse(time.RFC3339, p.GetDiscoveredAt())
		ports = append(ports, domain.Port{
			ID:             p.GetId(),
			AssetID:        assetUUID.String(),
			PortNumber:     int(p.GetPortNumber()),
			Protocol:       p.GetProtocol(),
			State:          p.GetState(),
			ServiceName:    p.GetServiceName(),
			ServiceVersion: p.GetServiceVersion(),
			Description:    p.GetDescription(),
			DiscoveredAt:   dt,
		})
	}

	// Prepare asset IPs
	ips := make([]domain.AssetIP, 0, len(req.GetAssetIps()))
	for _, ip := range req.GetAssetIps() {
		ips = append(ips, domain.AssetIP{
			AssetID:    assetUUID.String(),
			IP:         ip.GetIp(),
			MACAddress: ip.GetMacAddress(),
		})
	}

	assetDomain := domain.AssetDomain{
		ID:               assetUUID,
		Name:             req.GetName(),
		Domain:           req.GetDomain(),
		Hostname:         req.GetHostname(),
		OSName:           req.GetOsName(),
		OSVersion:        req.GetOsVersion(),
		Type:             req.GetType(),
		Description:      req.GetDescription(),
		Risk:             int(req.GetRisk()),
		LoggingCompleted: req.GetLoggingCompleted(),
		AssetValue:       int(req.GetAssetValue()),
		CreatedAt:        now,
		UpdatedAt:        now,
		Ports:            ports,
		AssetIPs:         ips,
	}

	if err := s.service.UpdateAsset(ctx, assetDomain); err != nil {
		return nil, err
	}

	return &pb.UpdateAssetResponse{}, nil
}

func (s *AssetService) DeleteAssets(ctx context.Context, req *pb.DeleteAssetsRequest) (*pb.DeleteAssetsResponse, error) {
	// Convert the filter from proto to domain if present
	var filter *domain.AssetFilters
	if req.Filter != nil {
		f := domain.AssetFilters{
			Name:        req.GetFilter().GetName(),
			Domain:      req.GetFilter().GetDomain(),
			Hostname:    req.GetFilter().GetHostname(),
			OSName:      req.GetFilter().GetOsName(),
			OSVersion:   req.GetFilter().GetOsVersion(),
			Type:        req.GetFilter().GetType(),
			IP:          req.GetFilter().GetIp(),
			ScannerType: req.GetFilter().GetScannerType(),
			Network:     req.GetFilter().GetNetwork(),
		}
		filter = &f
	}

	err := s.service.DeleteAssets(ctx, req.Ids, filter, req.GetExclude())
	if err != nil {
		return nil, err
	}

	return &pb.DeleteAssetsResponse{
		Success: true,
	}, nil
}

func (s *AssetService) ExportAssets(ctx context.Context, req *pb.ExportAssetsRequest) ([]byte, error) {
	assetUUIDs := []domain.AssetUUID{}

	// Check if we need to export all assets
	if len(req.GetAssetIds()) == 1 && req.GetAssetIds()[0] == "All" {
		// Empty assetUUIDs means export all assets
	} else {
		// Parse individual asset IDs
		for _, id := range req.GetAssetIds() {
			assetUUID, err := uuid.Parse(id)
			if err != nil {
				return nil, ErrInvalidAssetUUID
			}
			assetUUIDs = append(assetUUIDs, assetUUID)
		}
	}

	// Map export type from PB to domain
	var exportType domain.ExportType

	switch req.GetExportType() {
	case pb.ExportType_FULL_EXPORT:
		exportType = domain.FullExport
	case pb.ExportType_SELECTED_COLUMNS:
		exportType = domain.SelectedColumnsExport
	default:
		exportType = domain.FullExport
	}

	exportData, err := s.service.ExportAssets(ctx, assetUUIDs, exportType, req.GetSelectedColumns())
	if err != nil {
		return nil, err
	}

	csvData, err := s.service.GenerateCSV(ctx, exportData)
	if err != nil {
		return nil, err
	}

	return csvData, nil
}

// GetDistinctOSNames returns a list of all distinct OS names from assets
func (s *AssetService) GetDistinctOSNames(ctx context.Context, req *pb.GetDistinctOSNamesRequest) (*pb.GetDistinctOSNamesResponse, error) {
	osNames, err := s.service.GetDistinctOSNames(ctx)
	if err != nil {
		return nil, err
	}

	return &pb.GetDistinctOSNamesResponse{
		OsNames: osNames,
	}, nil
}

func domainToPbAsset(asset domain.AssetDomain) *pb.Asset {
	// Convert ports to protobuf format
	pbPorts := make([]*pb.Port, 0, len(asset.Ports))
	for _, port := range asset.Ports {
		pbPorts = append(pbPorts, &pb.Port{
			Id:             port.ID,
			AssetId:        port.AssetID,
			PortNumber:     int32(port.PortNumber),
			Protocol:       port.Protocol,
			State:          port.State,
			ServiceName:    port.ServiceName,
			ServiceVersion: port.ServiceVersion,
			Description:    port.Description,
			DiscoveredAt:   port.DiscoveredAt.Format("2006-01-02 15:04:05"),
		})
	}

	// Convert VMware VMs to protobuf format
	pbVMwareVMs := make([]*pb.VMwareVM, 0, len(asset.VMwareVMs))
	for _, vm := range asset.VMwareVMs {
		pbVMwareVMs = append(pbVMwareVMs, &pb.VMwareVM{
			VmId:         vm.VMID,
			AssetId:      vm.AssetID,
			VmName:       vm.VMName,
			Hypervisor:   vm.Hypervisor,
			CpuCount:     int32(vm.CPUCount),
			MemoryMb:     int32(vm.MemoryMB),
			DiskSizeGb:   int32(vm.DiskSizeGB),
			PowerState:   vm.PowerState,
			LastSyncedAt: vm.LastSyncedAt.Format("2006-01-02 15:04:05"),
		})
	}

	// Convert asset IPs to protobuf format
	pbAssetIPs := make([]*pb.AssetIP, 0, len(asset.AssetIPs))
	for _, ip := range asset.AssetIPs {
		pbAssetIPs = append(pbAssetIPs, &pb.AssetIP{
			AssetId:    ip.AssetID,
			Ip:         ip.IP,
			MacAddress: ip.MACAddress,
		})
	}

	// Convert scanner info to protobuf format
	var pbScanner *pb.Scanner
	if asset.Scanner != nil {
		pbScanner = &pb.Scanner{
			Type: asset.Scanner.Type,
		}
	} else {
		pbScanner = &pb.Scanner{
			Type: "",
		}
	}

	return &pb.Asset{
		Id:               asset.ID.String(),
		Name:             asset.Name,
		Domain:           asset.Domain,
		Hostname:         asset.Hostname,
		OsName:           asset.OSName,
		OsVersion:        asset.OSVersion,
		Type:             asset.Type,
		Description:      asset.Description,
		Risk:             int32(asset.Risk),
		LoggingCompleted: asset.LoggingCompleted,
		AssetValue:       int32(asset.AssetValue),
		CreatedAt:        asset.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:        asset.UpdatedAt.Format("2006-01-02 15:04:05"),
		Ports:            pbPorts,
		VmwareVms:        pbVMwareVMs,
		AssetIps:         pbAssetIPs,
		Scanner:          pbScanner,
	}
}
