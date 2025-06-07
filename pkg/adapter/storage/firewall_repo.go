package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/gorm"
)

// FirewallRepo handles firewall-specific database operations
type FirewallRepo struct {
	db *gorm.DB
}

// NewFirewallRepo creates a new firewall repository
func NewFirewallRepo(db *gorm.DB) *FirewallRepo {
	return &FirewallRepo{db: db}
}

// CreateFirewallTables creates all firewall-related tables
func (r *FirewallRepo) CreateFirewallTables(ctx context.Context) error {
	log.Println("Creating firewall database tables...")

	// Create tables in the correct order (considering foreign key dependencies)
	tables := []interface{}{
		&types.FirewallVendor{},
		&types.InterfaceType{},
		&types.Firewall{},
		&types.SecurityZone{},
		&types.FirewallInterface{},
		&types.VLAN{},
		&types.InterfaceIP{},
		&types.SecurityPolicy{},
		&types.VendorConfig{},
		&types.FirewallScanJob{},
	}

	// Create tables
	for _, table := range tables {
		if err := r.db.WithContext(ctx).AutoMigrate(table); err != nil {
			return fmt.Errorf("failed to create table %T: %v", table, err)
		}
	}

	// Insert initial data
	if err := r.insertInitialData(ctx); err != nil {
		return fmt.Errorf("failed to insert initial data: %v", err)
	}

	log.Println("All firewall tables created successfully")
	return nil
}

// insertInitialData inserts initial reference data
func (r *FirewallRepo) insertInitialData(ctx context.Context) error {
	// Insert firewall vendors
	vendors := []types.FirewallVendor{
		{VendorName: "Fortinet", VendorCode: "FORTI"},
		{VendorName: "Palo Alto Networks", VendorCode: "PALO"},
		{VendorName: "Cisco", VendorCode: "CISCO"},
		{VendorName: "pfSense", VendorCode: "PFSENSE"},
		{VendorName: "SonicWall", VendorCode: "SONIC"},
		{VendorName: "Juniper", VendorCode: "JUNIPER"},
		{VendorName: "Check Point", VendorCode: "CHECKPOINT"},
		{VendorName: "WatchGuard", VendorCode: "WATCHGUARD"},
		{VendorName: "Sophos", VendorCode: "SOPHOS"},
	}

	for _, vendor := range vendors {
		err := r.db.WithContext(ctx).FirstOrCreate(&vendor, types.FirewallVendor{VendorCode: vendor.VendorCode}).Error
		if err != nil {
			return err
		}
	}

	// Insert interface types
	interfaceTypes := []types.InterfaceType{
		{TypeName: "ethernet", Description: stringPtr("Physical Ethernet interface")},
		{TypeName: "vlan", Description: stringPtr("VLAN subinterface")},
		{TypeName: "loopback", Description: stringPtr("Loopback interface")},
		{TypeName: "tunnel", Description: stringPtr("Tunnel interface (VPN, GRE, etc.)")},
		{TypeName: "aggregate", Description: stringPtr("Link aggregation/bonding")},
		{TypeName: "redundant", Description: stringPtr("Redundant interface")},
		{TypeName: "virtual-wire", Description: stringPtr("Virtual wire interface")},
		{TypeName: "layer2", Description: stringPtr("Layer 2 interface")},
		{TypeName: "management", Description: stringPtr("Management interface")},
		{TypeName: "ha", Description: stringPtr("High Availability interface")},
		{TypeName: "virtual-router", Description: stringPtr("Virtual router interface")},
	}

	for _, ifType := range interfaceTypes {
		err := r.db.WithContext(ctx).FirstOrCreate(&ifType, types.InterfaceType{TypeName: ifType.TypeName}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// FirewallData represents the complete firewall configuration data
type FirewallData struct {
	FirewallID int64
	Zones      []ZoneData
	Interfaces []InterfaceData
	Policies   []PolicyData
	VLANs      []VLANData
}

type ZoneData struct {
	Name        string
	Description string
	Interfaces  []string
}

type InterfaceData struct {
	Name         string
	IP           string
	Status       string
	Description  string
	MTU          int
	Speed        string
	Duplex       string
	Type         string
	VDOM         string
	Mode         string
	Role         string
	MacAddr      string
	Allowaccess  []string
	SecondaryIPs []SecondaryIPData
	Zone         string
}

type SecondaryIPData struct {
	ID          int
	IP          string
	Allowaccess []string
}

type PolicyData struct {
	PolicyID int
	Name     string
	SrcIntf  []string
	DstIntf  []string
	SrcAddr  []string
	DstAddr  []string
	Service  []string
	Action   string
	Status   string
	Schedule string
}

type VLANData struct {
	VLANID          int
	VLANName        string
	ParentInterface string
	Description     string
}

// StoreFirewallData stores complete firewall configuration data
func (r *FirewallRepo) StoreFirewallData(ctx context.Context, data FirewallData, scanJobID int64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Store zones
		zoneMap, err := r.storeZones(tx, data.FirewallID, data.Zones)
		if err != nil {
			return fmt.Errorf("failed to store zones: %v", err)
		}

		// Store interfaces
		interfaceMap, err := r.storeInterfaces(tx, data.FirewallID, data.Interfaces, zoneMap)
		if err != nil {
			return fmt.Errorf("failed to store interfaces: %v", err)
		}

		// Store policies
		if err := r.storePolicies(tx, data.FirewallID, data.Policies, zoneMap); err != nil {
			return fmt.Errorf("failed to store policies: %v", err)
		}

		// Store VLANs
		if err := r.storeVLANs(tx, data.FirewallID, data.VLANs, interfaceMap); err != nil {
			return fmt.Errorf("failed to store VLANs: %v", err)
		}

		// Link firewall to scan job
		if err := r.linkFirewallToScanJob(tx, data.FirewallID, scanJobID); err != nil {
			return fmt.Errorf("failed to link firewall to scan job: %v", err)
		}

		return nil
	})
}

// CreateOrUpdateFirewall creates or updates a firewall device
func (r *FirewallRepo) CreateOrUpdateFirewall(ctx context.Context, managementIP, hostname string) (int64, error) {
	// Get Fortinet vendor ID
	var vendor types.FirewallVendor
	if err := r.db.WithContext(ctx).Where("vendor_code = ?", "FORTI").First(&vendor).Error; err != nil {
		return 0, fmt.Errorf("failed to get vendor: %v", err)
	}

	// Create or update firewall
	firewall := types.Firewall{
		VendorID:     vendor.ID,
		Hostname:     hostname,
		ManagementIP: managementIP,
		SiteName:     stringPtr("Default Site"),
		Location:     stringPtr("Default Location"),
		IsHAEnabled:  false,
		HARole:       "standalone",
		LastSync:     timePtr(time.Now()),
		SyncStatus:   "success",
	}

	// Use FirstOrCreate to avoid duplicates
	var existingFirewall types.Firewall
	err := r.db.WithContext(ctx).Where("management_ip = ? AND hostname = ?", managementIP, hostname).
		FirstOrCreate(&existingFirewall, firewall).Error

	if err != nil {
		return 0, fmt.Errorf("failed to create/update firewall: %v", err)
	}

	// Update LastSync for existing firewall
	if existingFirewall.ID != 0 {
		r.db.WithContext(ctx).Model(&existingFirewall).Updates(map[string]interface{}{
			"last_sync":   time.Now(),
			"sync_status": "success",
		})
	}

	return existingFirewall.ID, nil
}

// storeZones stores security zones
func (r *FirewallRepo) storeZones(tx *gorm.DB, firewallID int64, zones []ZoneData) (map[string]int64, error) {
	zoneMap := make(map[string]int64)

	for _, zone := range zones {
		securityZone := types.SecurityZone{
			FirewallID:      firewallID,
			ZoneName:        zone.Name,
			ZoneType:        "security",
			VendorZoneType:  stringPtr("fortigate_zone"),
			Description:     stringPtr(zone.Description),
			ZoneMode:        "layer3",
			IntrazoneAction: "allow",
		}

		var existingZone types.SecurityZone
		err := tx.Where("firewall_id = ? AND zone_name = ?", firewallID, zone.Name).
			FirstOrCreate(&existingZone, securityZone).Error
		if err != nil {
			return nil, err
		}

		zoneMap[zone.Name] = existingZone.ID
	}

	return zoneMap, nil
}

// storeInterfaces stores network interfaces
func (r *FirewallRepo) storeInterfaces(tx *gorm.DB, firewallID int64, interfaces []InterfaceData, zoneMap map[string]int64) (map[string]int64, error) {
	interfaceMap := make(map[string]int64)

	for _, intf := range interfaces {
		// Get interface type
		interfaceTypeID, err := r.getInterfaceTypeID(tx, intf.Name)
		if err != nil {
			log.Printf("Failed to get interface type for '%s': %v", intf.Name, err)
			continue
		}

		// Get zone assignment
		var zoneID *int64
		if intf.Zone != "" {
			if id, exists := zoneMap[intf.Zone]; exists {
				zoneID = &id
			}
		}

		// Parse IP configuration
		ipAddress, netmask, cidrPrefix := r.parseIPNetmask(intf.IP)

		// Handle VLAN interfaces
		var parentInterfaceID *int64
		var vlanID *int
		if strings.Contains(intf.Name, ".") {
			parts := strings.Split(intf.Name, ".")
			if len(parts) == 2 {
				if vlanIDInt, err := strconv.Atoi(parts[1]); err == nil {
					vlanID = &vlanIDInt
				}
			}
		}

		// Build vendor-specific config
		vendorConfig := map[string]interface{}{
			"allowaccess":     intf.Allowaccess,
			"status":          intf.Status,
			"type":            intf.Type,
			"vdom":            intf.VDOM,
			"mode":            intf.Mode,
			"role":            intf.Role,
			"original_duplex": intf.Duplex,
			"original_speed":  intf.Speed,
			"secondaryip":     intf.SecondaryIPs,
		}

		vendorConfigJSON, _ := json.Marshal(vendorConfig)

		// Create interface
		firewallInterface := types.FirewallInterface{
			FirewallID:           firewallID,
			InterfaceName:        intf.Name,
			InterfaceTypeID:      interfaceTypeID,
			ZoneID:               zoneID,
			IPAddress:            stringPtr(ipAddress),
			Netmask:              stringPtr(netmask),
			CIDRPrefix:           intPtr(cidrPrefix),
			Description:          stringPtr(intf.Description),
			OperationalStatus:    r.normalizeStatus(intf.Status, "operational"),
			AdminStatus:          r.normalizeStatus(intf.Status, "admin"),
			MTU:                  r.normalizeMTU(intf.MTU),
			Speed:                stringPtr(intf.Speed),
			Duplex:               r.normalizeDuplex(intf.Duplex),
			ParentInterfaceID:    parentInterfaceID,
			VLANID:               vlanID,
			MACAddress:           stringPtr(intf.MacAddr),
			VendorSpecificConfig: stringPtr(string(vendorConfigJSON)),
		}

		var existingInterface types.FirewallInterface
		err = tx.Where("firewall_id = ? AND interface_name = ?", firewallID, intf.Name).
			FirstOrCreate(&existingInterface, firewallInterface).Error
		if err != nil {
			log.Printf("Failed to create interface '%s': %v", intf.Name, err)
			continue
		}

		interfaceMap[intf.Name] = existingInterface.ID

		// Store interface IPs
		if err := r.storeInterfaceIPs(tx, existingInterface.ID, intf); err != nil {
			log.Printf("Failed to store IPs for interface '%s': %v", intf.Name, err)
		}
	}

	// Update parent interface relationships
	r.updateVLANParentRelationships(tx, interfaceMap)

	return interfaceMap, nil
}

// storeInterfaceIPs stores IP addresses for an interface
func (r *FirewallRepo) storeInterfaceIPs(tx *gorm.DB, interfaceID int64, intf InterfaceData) error {
	// Store primary IP
	if intf.IP != "" && intf.IP != "0.0.0.0 0.0.0.0" {
		ipAddress, netmask, cidrPrefix := r.parseIPNetmask(intf.IP)
		if ipAddress != "" {
			err := r.createInterfaceIP(tx, interfaceID, ipAddress, netmask, cidrPrefix, "ipv4", "primary")
			if err != nil {
				return err
			}
		}
	}

	// Store secondary IPs
	for _, secIP := range intf.SecondaryIPs {
		if secIP.IP != "" && secIP.IP != "0.0.0.0 0.0.0.0" {
			ipAddress, netmask, cidrPrefix := r.parseIPNetmask(secIP.IP)
			if ipAddress != "" {
				err := r.createInterfaceIP(tx, interfaceID, ipAddress, netmask, cidrPrefix, "ipv4", "secondary")
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// createInterfaceIP creates a single interface IP record
func (r *FirewallRepo) createInterfaceIP(tx *gorm.DB, interfaceID int64, ipAddress, netmask string, cidrPrefix int, ipVersion, ipType string) error {
	interfaceIP := types.InterfaceIP{
		InterfaceID: interfaceID,
		IPAddress:   ipAddress,
		Netmask:     stringPtr(netmask),
		CIDRPrefix:  intPtr(cidrPrefix),
		IPVersion:   ipVersion,
		IPType:      ipType,
	}

	return tx.FirstOrCreate(&interfaceIP, types.InterfaceIP{
		InterfaceID: interfaceID,
		IPAddress:   ipAddress,
		IPVersion:   ipVersion,
	}).Error
}

// storePolicies stores security policies
func (r *FirewallRepo) storePolicies(tx *gorm.DB, firewallID int64, policies []PolicyData, zoneMap map[string]int64) error {
	for _, policy := range policies {
		policyName := policy.Name
		if policyName == "" {
			policyName = fmt.Sprintf("Policy_%d", policy.PolicyID)
		}

		// Map FortiGate action to standard action
		action := "deny"
		if policy.Action == "accept" {
			action = "allow"
		}

		status := "disabled"
		if policy.Status == "enable" {
			status = "enabled"
		}

		// Build vendor config
		vendorConfig := map[string]interface{}{
			"srcintf":  policy.SrcIntf,
			"dstintf":  policy.DstIntf,
			"srcaddr":  policy.SrcAddr,
			"dstaddr":  policy.DstAddr,
			"service":  policy.Service,
			"schedule": policy.Schedule,
		}

		vendorConfigJSON, _ := json.Marshal(vendorConfig)

		securityPolicy := types.SecurityPolicy{
			FirewallID:           firewallID,
			PolicyName:           stringPtr(policyName),
			PolicyID:             intPtr(policy.PolicyID),
			Action:               action,
			PolicyType:           "security",
			Status:               status,
			RuleOrder:            intPtr(policy.PolicyID),
			VendorSpecificConfig: stringPtr(string(vendorConfigJSON)),
		}

		var existingPolicy types.SecurityPolicy
		err := tx.Where("firewall_id = ? AND policy_id = ?", firewallID, policy.PolicyID).
			FirstOrCreate(&existingPolicy, securityPolicy).Error
		if err != nil {
			log.Printf("Failed to create policy '%s': %v", policyName, err)
			continue
		}
	}

	return nil
}

// storeVLANs stores VLAN configurations
func (r *FirewallRepo) storeVLANs(tx *gorm.DB, firewallID int64, vlans []VLANData, interfaceMap map[string]int64) error {
	for _, vlan := range vlans {
		parentInterfaceID, exists := interfaceMap[vlan.ParentInterface]
		if !exists {
			log.Printf("Parent interface '%s' not found for VLAN %d", vlan.ParentInterface, vlan.VLANID)
			continue
		}

		vlanInterface := fmt.Sprintf("%s.%d", vlan.ParentInterface, vlan.VLANID)
		var vlanInterfaceID *int64
		if id, exists := interfaceMap[vlanInterface]; exists {
			vlanInterfaceID = &id
		}

		vlanRecord := types.VLAN{
			FirewallID:        firewallID,
			VLANID:            vlan.VLANID,
			VLANName:          stringPtr(vlan.VLANName),
			ParentInterfaceID: parentInterfaceID,
			VLANInterfaceID:   vlanInterfaceID,
			Description:       stringPtr(vlan.Description),
			IsNative:          false,
		}

		var existingVLAN types.VLAN
		err := tx.Where("firewall_id = ? AND parent_interface_id = ? AND vlan_id = ?",
			firewallID, parentInterfaceID, vlan.VLANID).
			FirstOrCreate(&existingVLAN, vlanRecord).Error
		if err != nil {
			log.Printf("Failed to create VLAN %d: %v", vlan.VLANID, err)
			continue
		}
	}

	return nil
}

// linkFirewallToScanJob links firewall to scan job
func (r *FirewallRepo) linkFirewallToScanJob(tx *gorm.DB, firewallID, scanJobID int64) error {
	firewallScanJob := types.FirewallScanJob{
		FirewallID:   firewallID,
		ScanJobID:    scanJobID,
		DiscoveredAt: time.Now(),
	}

	return tx.FirstOrCreate(&firewallScanJob, types.FirewallScanJob{
		FirewallID: firewallID,
		ScanJobID:  scanJobID,
	}).Error
}

// Helper functions

func (r *FirewallRepo) getInterfaceTypeID(tx *gorm.DB, interfaceName string) (int64, error) {
	var interfaceType types.InterfaceType
	var typeName string

	interfaceNameLower := strings.ToLower(interfaceName)

	switch {
	case strings.Contains(interfaceName, ".") || strings.HasPrefix(interfaceNameLower, "vlan"):
		typeName = "vlan"
	case strings.HasPrefix(interfaceNameLower, "port"):
		typeName = "ethernet"
	case strings.HasPrefix(interfaceNameLower, "tunnel"):
		typeName = "tunnel"
	case strings.HasPrefix(interfaceNameLower, "loop"):
		typeName = "loopback"
	case strings.HasPrefix(interfaceNameLower, "agg"):
		typeName = "aggregate"
	case strings.HasPrefix(interfaceNameLower, "mgmt"):
		typeName = "management"
	default:
		typeName = "ethernet"
	}

	err := tx.Where("type_name = ?", typeName).First(&interfaceType).Error
	if err != nil {
		// Default to ethernet
		err = tx.Where("type_name = 'ethernet'").First(&interfaceType).Error
	}

	return interfaceType.ID, err
}

func (r *FirewallRepo) parseIPNetmask(ipString string) (string, string, int) {
	if ipString == "" || ipString == "0.0.0.0 0.0.0.0" {
		return "", "", 0
	}

	parts := strings.Fields(ipString)
	if len(parts) == 2 {
		ip := parts[0]
		netmask := parts[1]

		// Convert netmask to CIDR
		cidr := r.netmaskToCIDR(netmask)
		return ip, netmask, cidr
	}

	return ipString, "", 0
}

func (r *FirewallRepo) netmaskToCIDR(netmask string) int {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return 0
	}

	mask := net.IPMask(ip.To4())
	cidr, _ := mask.Size()
	return cidr
}

func (r *FirewallRepo) normalizeStatus(statusValue string, statusType string) string {
	if statusValue == "" {
		if statusType == "operational" {
			return "unknown"
		}
		return "up"
	}

	statusLower := strings.ToLower(strings.TrimSpace(statusValue))

	if statusType == "operational" {
		switch statusLower {
		case "up", "connected", "link-up":
			return "up"
		case "down", "disconnected", "link-down":
			return "down"
		default:
			return "unknown"
		}
	} else { // admin status
		switch statusLower {
		case "up", "enable", "enabled":
			return "up"
		case "down", "disable", "disabled":
			return "down"
		default:
			return "up"
		}
	}
}

func (r *FirewallRepo) normalizeDuplex(duplexValue string) string {
	if duplexValue == "" {
		return "auto"
	}

	duplexLower := strings.ToLower(strings.TrimSpace(duplexValue))

	switch duplexLower {
	case "full", "full-duplex":
		return "full"
	case "half", "half-duplex":
		return "half"
	case "auto", "auto-duplex", "auto-negotiate":
		return "auto"
	default:
		return "auto"
	}
}

func (r *FirewallRepo) normalizeMTU(mtu int) int {
	if mtu == 0 {
		return 1500
	}
	return mtu
}

func (r *FirewallRepo) updateVLANParentRelationships(tx *gorm.DB, interfaceMap map[string]int64) {
	for interfaceName, interfaceID := range interfaceMap {
		if strings.Contains(interfaceName, ".") {
			parentName := strings.Split(interfaceName, ".")[0]
			if parentID, exists := interfaceMap[parentName]; exists {
				tx.Model(&types.FirewallInterface{}).
					Where("id = ?", interfaceID).
					Update("parent_interface_id", parentID)
			}
		}
	}
}

// Helper functions for pointer conversions
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func intPtr(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}

func timePtr(t time.Time) *time.Time {
	return &t
}
