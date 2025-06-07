package scanner

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// VCenterRunner handles executing vCenter scans
type VCenterRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewVCenterRunner creates a new vCenter runner with asset repository
func NewVCenterRunner(assetRepo assetPort.Repo) *VCenterRunner {
	return &VCenterRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// ExecuteVCenterScan runs a vCenter scan based on scanner configuration
func (r *VCenterRunner) ExecuteVCenterScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("[VCenterScanner] Starting vCenter scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	log.Printf("[VCenterScanner] Scanner details: IP=%s, Port=%s, Username=%s",
		scanner.IP, scanner.Port, scanner.Username)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Build the vCenter connection URL
	vcenterURL := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%s", scanner.IP, scanner.Port),
		Path:   "/sdk",
	}

	// Set credentials
	vcenterURL.User = url.UserPassword(scanner.Username, scanner.Password)

	log.Printf("[VCenterScanner] Connecting to vCenter at: %s (without credentials)",
		fmt.Sprintf("https://%s:%s/sdk", scanner.IP, scanner.Port))

	// Set insecure flag to true to bypass certificate verification (for self-signed certs)
	insecure := true

	// Try to create a client with the standard method first
	client, err := govmomi.NewClient(scanCtx, vcenterURL, insecure)
	if err != nil {
		log.Printf("[VCenterScanner] Error connecting to vCenter using NewClient: %v", err)
		log.Printf("[VCenterScanner] Trying alternative connection method...")

		// Configure SOAP client with appropriate TLS settings
		soapClient := soap.NewClient(vcenterURL, insecure)
		soapClient.Timeout = time.Minute * 5

		// Create vim25 client
		vim25Client, err := vim25.NewClient(scanCtx, soapClient)
		if err != nil {
			log.Printf("[VCenterScanner] Error creating vim25 client: %v", err)
			return fmt.Errorf("vim25 client creation error: %w", err)
		}

		// Create govmomi client using the vim25 client
		client = &govmomi.Client{
			Client:         vim25Client,
			SessionManager: session.NewManager(vim25Client),
		}

		// Login
		err = client.Login(scanCtx, vcenterURL.User)
		if err != nil {
			log.Printf("[VCenterScanner] Login failed: %v", err)
			return fmt.Errorf("vCenter login error: %w", err)
		}
	}

	// Be sure to logout when done
	defer func() {
		log.Printf("[VCenterScanner] Logging out of vCenter")
		if logoutErr := client.Logout(context.Background()); logoutErr != nil {
			log.Printf("[VCenterScanner] Warning: Logout failed: %v", logoutErr)
		}
	}()

	// Print session info for logging purposes
	userSession, err := client.SessionManager.UserSession(scanCtx)
	if err != nil {
		log.Printf("[VCenterScanner] Unable to get session: %v", err)
		return fmt.Errorf("session retrieval error: %w", err)
	}
	log.Printf("[VCenterScanner] Successfully logged in to vCenter %s as: %s", scanner.IP, userSession.UserName)
	log.Printf("[VCenterScanner] Session details: FullName='%s', LoginTime='%v'",
		userSession.FullName, userSession.LoginTime)

	// Check if the context was cancelled
	if scanCtx.Err() == context.Canceled {
		log.Printf("[VCenterScanner] vCenter scan was cancelled for job ID: %d", scanJobID)
		return context.Canceled
	}

	// Create finder and get default datacenter
	finder := find.NewFinder(client.Client, true)

	// List all datacenters
	dcs, err := finder.DatacenterList(scanCtx, "*")
	if err != nil {
		log.Printf("[VCenterScanner] Error finding datacenters: %v", err)
		return fmt.Errorf("datacenter listing error: %w", err)
	}

	log.Printf("[VCenterScanner] Found %d datacenter(s)", len(dcs))

	// Process each datacenter
	for i, dc := range dcs {
		log.Printf("[VCenterScanner] Processing datacenter %d: %s", i+1, dc.Name())
		finder.SetDatacenter(dc)

		// Find all VMs in this datacenter
		vms, err := finder.VirtualMachineList(scanCtx, "*")
		if err != nil {
			log.Printf("[VCenterScanner] Error listing VMs in datacenter %s: %v", dc.Name(), err)
			// Continue with next datacenter
			continue
		}

		log.Printf("[VCenterScanner] Found %d VMs in datacenter %s", len(vms), dc.Name())

		// Create a property collector for efficient retrieval of VM properties
		pc := property.DefaultCollector(client.Client)
		var vmRefs []types.ManagedObjectReference
		for _, vm := range vms {
			vmRefs = append(vmRefs, vm.Reference())
		}

		// Define properties to retrieve
		var vmProps []mo.VirtualMachine
		err = pc.Retrieve(scanCtx, vmRefs, []string{"summary", "guest", "config", "runtime", "storage"}, &vmProps)
		if err != nil {
			log.Printf("[VCenterScanner] Error retrieving properties for VMs: %v", err)
			return fmt.Errorf("VM property retrieval error: %w", err)
		}

		// Process the VM list and store as assets
		for i, vmProp := range vmProps {
			// Check for cancellation periodically
			if i%10 == 0 && scanCtx.Err() == context.Canceled {
				log.Printf("[VCenterScanner] vCenter scan was cancelled during VM processing for job ID: %d", scanJobID)
				return context.Canceled
			}

			// Process this VM
			if err := r.processVM(scanCtx, client, vmProp, scanJobID); err != nil {
				log.Printf("[VCenterScanner] Error processing VM %s: %v", vmProp.Name, err)
				// Continue with other VMs
			}
		}
	}

	log.Printf("[VCenterScanner] Completed vCenter scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	return nil
}

// Helper function to extract OS name and version from the full OS string
func extractOSInfo(fullOSName string) (osName string, osVersion string) {
	log.Printf("[VCenterScanner] Extracting OS info from: %s", fullOSName)

	// Default values
	osName = fullOSName
	osVersion = ""

	// Common patterns:
	// Windows: "Microsoft Windows Server 2019 (64-bit)" or "Microsoft Windows 10 (64-bit)"
	// Linux: "Debian GNU/Linux 10 (64-bit)" or "Ubuntu Linux (64-bit)" or "CentOS 7 (64-bit)"
	// macOS: "macOS 12.3 (64-bit)"

	// Remove architecture info
	cleanName := fullOSName
	if idx := strings.Index(cleanName, "(64-bit)"); idx > 0 {
		cleanName = strings.TrimSpace(cleanName[:idx])
	} else if idx := strings.Index(cleanName, "(32-bit)"); idx > 0 {
		cleanName = strings.TrimSpace(cleanName[:idx])
	}

	// Extract OS family and version for different OS types
	switch {
	case strings.Contains(cleanName, "Windows"):
		osName = "Windows"

		// Handle Windows Server specifically
		if strings.Contains(cleanName, "Server") {
			osName = "Windows Server"

			// Extract version: Windows Server 2019, 2016, 2012, etc.
			parts := strings.Fields(cleanName)
			for _, part := range parts {
				if part == "2008" || part == "2012" || part == "2016" || part == "2019" || part == "2022" {
					osVersion = part
					break
				}
			}
		} else {
			// Extract version: Windows 10, 11, etc.
			parts := strings.Fields(cleanName)
			for _, part := range parts {
				if part == "7" || part == "8" || part == "8.1" || part == "10" || part == "11" {
					osVersion = part
					break
				}
			}
		}

	case strings.Contains(cleanName, "CentOS"):
		osName = "CentOS"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "Red Hat") || strings.Contains(cleanName, "RedHat") || strings.Contains(cleanName, "RHEL"):
		osName = "Red Hat Enterprise Linux"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "Ubuntu"):
		osName = "Ubuntu"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			// Check for patterns like "20.04" or "18.04"
			if strings.Contains(part, ".") && len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "Debian"):
		osName = "Debian"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "SUSE") || strings.Contains(cleanName, "SuSE"):
		osName = "SUSE Linux"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}

	case strings.Contains(cleanName, "macOS") || strings.Contains(cleanName, "Mac OS"):
		osName = "macOS"
		parts := strings.Fields(cleanName)
		for _, part := range parts {
			if strings.Contains(part, ".") && len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
				osVersion = part
				break
			}
		}
	}

	if osVersion == "" {
		// Try a general approach to extract version numbers if specific patterns didn't work
		for _, part := range strings.Fields(cleanName) {
			// Look for numbers or numbers with dots (like 10.15)
			if strings.ContainsAny(part, "0123456789") &&
				(len(part) <= 5 || strings.Contains(part, ".")) {
				osVersion = part
				break
			}
		}
	}

	log.Printf("[VCenterScanner] Extracted OS Name: %s, Version: %s", osName, osVersion)
	return osName, osVersion
}

// Helper function to extract MAC addresses from VM hardware configuration
func extractMACAddresses(vm mo.VirtualMachine) map[string]string {
	deviceToMAC := make(map[string]string)

	if vm.Config == nil || vm.Config.Hardware.Device == nil {
		return deviceToMAC
	}

	// Process each device in the VM configuration
	for _, device := range vm.Config.Hardware.Device {
		// Try to convert to network device
		if nic, ok := device.(types.BaseVirtualEthernetCard); ok {
			card := nic.GetVirtualEthernetCard()
			if card.MacAddress != "" {
				deviceKey := fmt.Sprintf("%d", card.Key)
				deviceToMAC[deviceKey] = card.MacAddress
				log.Printf("[VCenterScanner] Found MAC address %s for device key %s", card.MacAddress, deviceKey)
			}
		}
	}

	return deviceToMAC
}

// processVM processes a single VM and stores it as an asset
func (r *VCenterRunner) processVM(ctx context.Context, client *govmomi.Client, vm mo.VirtualMachine, scanJobID int64) error {
	// Validate VM name first
	vmName := strings.TrimSpace(vm.Name)
	if vmName == "" {
		log.Printf("[VCenterScanner] ERROR: VM has empty name, trying to get from Config")
		if vm.Config != nil && vm.Config.Name != "" {
			vmName = strings.TrimSpace(vm.Config.Name)
			log.Printf("[VCenterScanner] Using name from Config: %s", vmName)
		} else {
			log.Printf("[VCenterScanner] ERROR: VM still has empty name even from Config, skipping")
			return fmt.Errorf("VM has empty name")
		}
	}

	log.Printf("[VCenterScanner] Processing VM: '%s' (length: %d)", vmName, len(vmName))

	// We'll collect IP addresses from all network interfaces
	var ipAddresses []string
	var hostname string

	// Extract guest info
	if vm.Guest != nil {
		hostname = vm.Guest.HostName
		log.Printf("[VCenterScanner] VM %s - Guest hostname: %s", vmName, hostname)

		// Primary IP
		if vm.Guest.IpAddress != "" {
			ipAddresses = append(ipAddresses, vm.Guest.IpAddress)
			log.Printf("[VCenterScanner] VM %s - Primary IP: %s", vmName, vm.Guest.IpAddress)
		}

		// Additional IPs from network interfaces
		if vm.Guest.Net != nil {
			for _, net := range vm.Guest.Net {
				log.Printf("[VCenterScanner] VM %s - Network adapter: %s", vmName, net.Network)
				for _, ip := range net.IpAddress {
					// Check if this IP is already in our list
					alreadyAdded := false
					for _, existingIP := range ipAddresses {
						if existingIP == ip {
							alreadyAdded = true
							break
						}
					}

					if !alreadyAdded {
						// Skip IPv6 addresses (optional - remove if you want IPv6)
						if strings.Contains(ip, ":") {
							log.Printf("[VCenterScanner] VM %s - Skipping IPv6 address: %s", vmName, ip)
							continue
						}

						ipAddresses = append(ipAddresses, ip)
						log.Printf("[VCenterScanner] VM %s - Additional IP: %s", vmName, ip)
					}
				}
			}
		}
	}

	// Use name as hostname if guest hostname is not available
	if hostname == "" {
		hostname = vmName
		log.Printf("[VCenterScanner] VM %s - Using VM name as hostname", vmName)
	}

	// Get power state
	powerState := "Off"
	if vm.Runtime.PowerState == "poweredOn" {
		powerState = "On"
	} else if vm.Runtime.PowerState == "suspended" {
		powerState = "Suspended"
	}
	log.Printf("[VCenterScanner] VM %s - Power state: %s", vmName, powerState)

	// Get OS info
	var fullOSName string
	if vm.Guest != nil && vm.Guest.GuestFullName != "" {
		fullOSName = vm.Guest.GuestFullName
		log.Printf("[VCenterScanner] VM %s - OS (from Guest): %s", vmName, fullOSName)
	} else if vm.Config != nil && vm.Config.GuestFullName != "" {
		fullOSName = vm.Config.GuestFullName
		log.Printf("[VCenterScanner] VM %s - OS (from Config): %s", vmName, fullOSName)
	} else {
		fullOSName = "Unknown"
	}

	// Extract OS name and version
	osName, osVersion := extractOSInfo(fullOSName)
	log.Printf("[VCenterScanner] VM %s - Parsed OS: %s, Version: %s", vmName, osName, osVersion)

	// Create a new asset record
	assetID := uuid.New()
	asset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        vmName, // Use the validated VM name
		Hostname:    hostname,
		OSName:      osName,
		OSVersion:   osVersion,
		Type:        "Virtual",
		Description: fmt.Sprintf("VMware virtual machine discovered by vCenter scan (Job ID: %d)", scanJobID),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]assetDomain.AssetIP, 0), // Initialize AssetIPs
	}

	// Validate that Name is set before continuing
	if asset.Name == "" {
		log.Printf("[VCenterScanner] ERROR: Asset name is empty after setting, this shouldn't happen!")
		return fmt.Errorf("asset name is empty")
	}

	// Get MAC addresses from hardware configuration
	macAddresses := extractMACAddresses(vm)

	// Create a map to associate MAC addresses with IPs from Guest.Net
	macToIPs := make(map[string][]string)
	deviceToMAC := make(map[string]string)

	// First pass: collect all MAC addresses and their associated IPs from Guest.Net
	if vm.Guest.Net != nil {
		for _, net := range vm.Guest.Net {
			if net.MacAddress != "" {
				log.Printf("[VCenterScanner] VM %s - Network adapter: %s, MAC: %s", vmName, net.Network, net.MacAddress)

				// Store MAC address
				for _, ip := range net.IpAddress {
					// Skip IPv6 addresses if that's still desired
					if strings.Contains(ip, ":") {
						continue
					}
					macToIPs[net.MacAddress] = append(macToIPs[net.MacAddress], ip)
				}
			}

			// Also map device key to MAC address for correlating with hardware config
			if net.DeviceConfigId > 0 {
				deviceKey := fmt.Sprintf("%d", net.DeviceConfigId)
				if mac, exists := macAddresses[deviceKey]; exists {
					deviceToMAC[deviceKey] = mac
				}
			}
		}
	}

	// Now add each IP with its corresponding MAC address
	for _, ip := range ipAddresses {
		mac := ""

		// First try to find the MAC address for this IP from Guest.Net
		for macAddr, ips := range macToIPs {
			for _, macIP := range ips {
				if macIP == ip {
					mac = macAddr
					break
				}
			}
			if mac != "" {
				break
			}
		}

		// If MAC not found and this is the primary IP, try the hardware configuration
		if mac == "" && ip == vm.Guest.IpAddress && vm.Guest.Net != nil && len(vm.Guest.Net) > 0 {
			// Use MAC from first network adapter as fallback for primary IP
			if vm.Guest.Net[0].MacAddress != "" {
				mac = vm.Guest.Net[0].MacAddress
			} else if vm.Guest.Net[0].DeviceConfigId > 0 {
				deviceKey := fmt.Sprintf("%d", vm.Guest.Net[0].DeviceConfigId)
				if hwMac, exists := macAddresses[deviceKey]; exists {
					mac = hwMac
				}
			}
		}

		asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
			AssetID:    asset.ID.String(),
			IP:         ip,
			MACAddress: mac, 
		})

		if mac != "" {
			log.Printf("[VCenterScanner] VM %s - Added IP: %s with MAC: %s", vmName, ip, mac)
		} else {
			log.Printf("[VCenterScanner] VM %s - Added IP: %s (no MAC available)", vmName, ip)
		}
	}

	log.Printf("[VCenterScanner] Creating asset for VM '%s' with ID %s and %d IPs (Name field: '%s')",
		vmName, assetID, len(asset.AssetIPs), asset.Name)

	// Log the asset details before storing
	log.Printf("[VCenterScanner] Asset to be stored - Name: '%s', Hostname: '%s', Type: '%s'",
		asset.Name, asset.Hostname, asset.Type)

	// Store the asset
	var err error
	var storedAssetID assetDomain.AssetUUID
	var isNewAsset bool = true

	// We'll retry a few times in case of transient issues
	for retries := 0; retries < 3; retries++ {
		log.Printf("[VCenterScanner] Attempting to create asset (retry %d) - Name: '%s'", retries, asset.Name)
		storedAssetID, err = r.assetRepo.Create(ctx, asset)
		if err == nil {
			isNewAsset = true
			log.Printf("[VCenterScanner] Successfully created new asset with ID: %s, Name: '%s'", storedAssetID, asset.Name)
			break
		}

		// Check if it's a duplicate error (asset may already exist)
		if strings.Contains(err.Error(), "Duplicate") {
			log.Printf("[VCenterScanner] VM %s - Duplicate asset, searching for existing asset", vm.Name)

			// Try to find the existing asset by hostname or IP
			filter := assetDomain.AssetFilters{
				Hostname: hostname,
			}

			// If we have IPs, search by the first one
			if len(ipAddresses) > 0 && ipAddresses[0] != "" {
				filter.IP = ipAddresses[0]
			}

			existingAssets, err := r.assetRepo.Get(ctx, filter)
			if err == nil && len(existingAssets) > 0 {
				// Update the existing asset with new information
				existingAsset := existingAssets[0]
				storedAssetID = existingAsset.ID
				isNewAsset = false

				log.Printf("[VCenterScanner] VM %s - Found existing asset with ID: %s, current name: '%s'",
					vmName, storedAssetID, existingAsset.Name)

				// Update the existing asset with the latest information
				existingAsset.Name = vmName // Use the validated VM name
				existingAsset.Hostname = hostname
				existingAsset.OSName = osName
				existingAsset.OSVersion = osVersion
				existingAsset.Type = "Virtual"
				existingAsset.Description = fmt.Sprintf("VMware virtual machine discovered by vCenter scan (Job ID: %d)", scanJobID)
				existingAsset.UpdatedAt = time.Now()
				existingAsset.AssetIPs = asset.AssetIPs // Update IP addresses

				log.Printf("[VCenterScanner] VM %s - Updating asset with Name='%s', Hostname='%s'",
					vmName, existingAsset.Name, existingAsset.Hostname)

				// Update the asset in the database
				err = r.assetRepo.Update(ctx, existingAsset)
				if err != nil {
					log.Printf("[VCenterScanner] VM %s - Error updating existing asset: %v", vmName, err)
					// Continue with retry
				} else {
					log.Printf("[VCenterScanner] VM %s - Successfully updated existing asset with ID: %s (Name: '%s')",
						vmName, storedAssetID, existingAsset.Name)
					break
				}
			}

			// If we couldn't find or update an existing asset, try with a new ID
			assetID = uuid.New()
			asset.ID = assetID
			log.Printf("[VCenterScanner] VM %s - Retrying with new asset ID: %s", vm.Name, assetID)
		} else {
			// Some other error
			log.Printf("[VCenterScanner] Error creating asset for VM %s: %v", vm.Name, err)
			time.Sleep(500 * time.Millisecond) // Brief pause before retry
		}
	}

	if err != nil && !isNewAsset {
		log.Printf("[VCenterScanner] Failed to create or update asset after retries: %v", err)
		return err
	}

	// Link the asset to the scan job
	err = r.assetRepo.LinkAssetToScanJob(ctx, storedAssetID, scanJobID)
	if err != nil {
		log.Printf("[VCenterScanner] Error linking asset to scan job: %v", err)
		// Non-fatal error, continue processing
	}

	// Get hardware info
	var cpuCount int32 = 0
	var memoryMB int32 = 0
	var totalDiskGB int = 0

	if vm.Config != nil && vm.Config.Hardware.NumCPU > 0 {
		cpuCount = vm.Config.Hardware.NumCPU
		memoryMB = vm.Config.Hardware.MemoryMB

		log.Printf("[VCenterScanner] VM %s - Hardware: CPU=%d, Memory=%d MB",
			vm.Name, cpuCount, memoryMB)
	}

	// Calculate total disk size
	if vm.Storage != nil {
		var totalStorage int64
		for _, usage := range vm.Storage.PerDatastoreUsage {
			totalStorage += usage.Committed + usage.Uncommitted
		}
		totalDiskGB = int(totalStorage / (1024 * 1024 * 1024))
		log.Printf("[VCenterScanner] VM %s - Total disk size: %d GB", vm.Name, totalDiskGB)
	}

	// Get hypervisor info
	hypervisor := "VMware vSphere"
	if vm.Runtime.Host != nil {
		var host mo.HostSystem
		err := client.RetrieveOne(ctx, *vm.Runtime.Host, []string{"config.product"}, &host)
		if err == nil && host.Config != nil {
			hypervisor = fmt.Sprintf("%s %s (Build %s)",
				host.Config.Product.Name,
				host.Config.Product.Version,
				host.Config.Product.Build)
			log.Printf("[VCenterScanner] VM %s - Hypervisor: %s", vm.Name, hypervisor)
		}
	}

	// Create VMware VM record with validated VM name
	vmRecord := assetDomain.VMwareVM{
		VMID:         vm.Config.InstanceUuid,
		AssetID:      storedAssetID.String(),
		VMName:       vmName, // Use the validated VM name
		Hypervisor:   hypervisor,
		CPUCount:     cpuCount,
		MemoryMB:     memoryMB,
		DiskSizeGB:   totalDiskGB,
		PowerState:   powerState,
		LastSyncedAt: time.Now(),
	}

	log.Printf("[VCenterScanner] Storing VMware VM data - VMName: '%s', AssetID: %s", vmRecord.VMName, storedAssetID)

	// Store VMware VM data
	if err := r.storeVMwareVMData(ctx, vmRecord); err != nil {
		log.Printf("[VCenterScanner] Error storing VMware VM data for %s: %v", vm.Name, err)
		// Continue processing - this is supplementary data
	}

	log.Printf("[VCenterScanner] Successfully processed VM: %s (Asset ID: %s)", vm.Name, storedAssetID)
	return nil
}

// Helper method to store VMware VM data
func (r *VCenterRunner) storeVMwareVMData(ctx context.Context, vmData assetDomain.VMwareVM) error {
	log.Printf("[VCenterScanner] Storing VM data for '%s' to database (Asset ID: %s)", vmData.VMName, vmData.AssetID)

	// First, verify that the asset exists in the assets table
	assetID, err := assetDomain.AssetUUIDFromString(vmData.AssetID)
	if err != nil {
		log.Printf("[VCenterScanner] Invalid asset UUID format for VM %s: %v", vmData.VMName, err)
		return fmt.Errorf("invalid asset UUID: %w", err)
	}

	var assetIdsList []assetDomain.AssetUUID
	assetIdsList = append(assetIdsList, assetID)

	// Check if the asset exists
	assets, err := r.assetRepo.GetByIDs(ctx, assetIdsList)
	if err != nil {
		log.Printf("[VCenterScanner] Error retrieving asset for VM %s: %v", vmData.VMName, err)
		return fmt.Errorf("error checking asset existence: %w", err)
	}

	if len(assets) == 0 {
		log.Printf("[VCenterScanner] Asset with ID %s does not exist for VM %s, cannot store VM data", vmData.AssetID, vmData.VMName)
		return fmt.Errorf("asset with ID %s does not exist", vmData.AssetID)
	}

	// Ensure the VM name is properly set before storing
	if vmData.VMName == "" {
		log.Printf("[VCenterScanner] Warning: VM name is empty for VM ID %s, this shouldn't happen", vmData.VMID)
	}

	// Now we know the asset exists, proceed with storing VM data
	err = r.assetRepo.StoreVMwareVM(ctx, vmData)
	if err != nil {
		log.Printf("[VCenterScanner] Error storing VM data for %s in database: %v", vmData.VMName, err)
		return err
	}

	log.Printf("[VCenterScanner] Successfully stored VM data for '%s' (VM ID: %s, Asset ID: %s)",
		vmData.VMName, vmData.VMID, vmData.AssetID)
	return nil
}

// CancelScan cancels a running scan job
func (r *VCenterRunner) CancelScan(jobID int64) bool {
	log.Printf("[VCenterScanner] Cancelling scan job ID: %d", jobID)
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *VCenterRunner) StatusScan(jobID int64) bool {
	status := r.cancelManager.HasActiveScan(jobID)
	log.Printf("[VCenterScanner] Status for scan job ID %d: %v", jobID, status)
	return status
}
