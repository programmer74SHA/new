package scanner

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vim25/mo"

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
	log.Printf("Starting vCenter scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Build the vCenter connection URL
	vcenterURL := &url.URL{
		Scheme: "https",
		Host:   scanner.IP + ":" + scanner.Port,
		Path:   "/sdk",
	}
	vcenterURL.User = url.UserPassword(scanner.Username, scanner.Password)

	// Create govmomi client
	client, err := govmomi.NewClient(scanCtx, vcenterURL, true)
	if err != nil {
		log.Printf("Error connecting to vCenter: %v", err)
		return fmt.Errorf("vCenter connection error: %w", err)
	}
	defer client.Logout(scanCtx)

	// Print session info for logging purposes
	sessionMgr := session.NewManager(client.Client)
	userSession, err := sessionMgr.UserSession(scanCtx)
	if err != nil {
		log.Printf("Unable to get session: %v", err)
		return fmt.Errorf("session retrieval error: %w", err)
	}
	log.Printf("Logged in to vCenter %s as: %s", scanner.IP, userSession.UserName)

	// Check if the context was cancelled
	if scanCtx.Err() == context.Canceled {
		log.Printf("vCenter scan was cancelled for job ID: %d", scanJobID)
		return context.Canceled
	}

	// Create finder and get default datacenter
	finder := find.NewFinder(client.Client, true)
	dc, err := finder.DefaultDatacenter(scanCtx)
	if err != nil {
		log.Printf("Error finding datacenter: %v", err)
		return fmt.Errorf("datacenter error: %w", err)
	}
	finder.SetDatacenter(dc)

	// Find all VMs
	vms, err := finder.VirtualMachineList(scanCtx, "*")
	if err != nil {
		log.Printf("Error listing VMs: %v", err)
		return fmt.Errorf("VM listing error: %w", err)
	}

	log.Printf("Found %d VMs in vCenter %s", len(vms), scanner.IP)

	// Process the VM list and store as assets
	for i, vm := range vms {
		// Check for cancellation periodically
		if i%10 == 0 && scanCtx.Err() == context.Canceled {
			log.Printf("vCenter scan was cancelled during VM processing for job ID: %d", scanJobID)
			return context.Canceled
		}

		var mvm mo.VirtualMachine
		err := vm.Properties(scanCtx, vm.Reference(), nil, &mvm)
		if err != nil {
			log.Printf("Error fetching properties for VM %s: %v", vm.Name(), err)
			continue
		}

		// Process this VM
		if err := r.processVM(scanCtx, client, mvm, scanJobID); err != nil {
			log.Printf("Error processing VM %s: %v", mvm.Name, err)
			// Continue with other VMs
		}
	}

	log.Printf("Completed vCenter scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	return nil
}

// processVM processes a single VM and stores it as an asset
func (r *VCenterRunner) processVM(ctx context.Context, client *govmomi.Client, vm mo.VirtualMachine, scanJobID int64) error {
	// We'll collect IP addresses from all network interfaces
	var ipAddresses []string
	var hostname string

	// Extract guest info
	if vm.Guest != nil {
		hostname = vm.Guest.HostName

		// Primary IP
		if vm.Guest.IpAddress != "" {
			ipAddresses = append(ipAddresses, vm.Guest.IpAddress)
		}

		// Additional IPs from network interfaces
		if vm.Guest.Net != nil {
			for _, net := range vm.Guest.Net {
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
						ipAddresses = append(ipAddresses, ip)
					}
				}
			}
		}
	}

	// Use name as hostname if guest hostname is not available
	if hostname == "" {
		hostname = vm.Name
	}

	// Skip if no IP addresses found (likely powered off VMs)
	if len(ipAddresses) == 0 {
		log.Printf("No IP addresses found for VM %s, skipping", vm.Name)
		return nil
	}

	// Get OS info
	osName := "Unknown"
	osVersion := ""
	if vm.Guest != nil && vm.Guest.GuestFullName != "" {
		osName = vm.Guest.GuestFullName
	} else if vm.Config != nil && vm.Config.GuestFullName != "" {
		osName = vm.Config.GuestFullName
	}

	// Create a new asset record
	asset := assetDomain.AssetDomain{
		ID:          uuid.New(),
		Name:        vm.Name,
		Hostname:    hostname,
		IPs:         ipAddresses,
		OSName:      osName,
		OSVersion:   osVersion,
		Type:        "Virtual",
		Description: fmt.Sprintf("Discovered by vCenter scan (Job ID: %d)", scanJobID),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store the asset
	assetID, err := r.assetRepo.Create(ctx, asset)
	if err != nil {
		return fmt.Errorf("error creating asset: %w", err)
	}

	// Link the asset to the scan job
	err = r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
	if err != nil {
		log.Printf("Error linking asset to scan job: %v", err)
	}

	// Create VMware VM record with additional details
	if vm.Config != nil {
		var totalDiskGB int
		if vm.Storage != nil {
			var totalStorage int64
			for _, usage := range vm.Storage.PerDatastoreUsage {
				totalStorage += usage.Committed + usage.Uncommitted
			}
			totalDiskGB = int(totalStorage / (1024 * 1024 * 1024))
		}

		// Store VM-specific info in VMwareVM table
		err = r.storeVMwareVM(ctx, assetID.String(), vm, client, totalDiskGB)
		if err != nil {
			log.Printf("Error storing VMware VM details: %v", err)
		}
	}

	log.Printf("Successfully processed VM: %s (Asset ID: %s)", vm.Name, assetID)
	return nil
}

// storeVMwareVM stores VMware-specific details about a VM
func (r *VCenterRunner) storeVMwareVM(ctx context.Context, assetID string, vm mo.VirtualMachine, client *govmomi.Client, diskSizeGB int) error {
	// Get power state
	powerState := "Off"
	if vm.Runtime.PowerState == "poweredOn" {
		powerState = "On"
	} else if vm.Runtime.PowerState == "suspended" {
		powerState = "Suspended"
	}

	// Get hypervisor info
	hypervisor := "VMware vSphere"
	if vm.Runtime.Host != nil {
		var host mo.HostSystem
		// Use the client instead of vm.Client() which doesn't exist
		err := client.RetrieveOne(ctx, *vm.Runtime.Host, nil, &host)
		if err == nil && host.Config != nil {
			hypervisor = fmt.Sprintf("%s %s (Build %s)",
				host.Config.Product.Name,
				host.Config.Product.Version,
				host.Config.Product.Build)
		}
	}

	// Create VMware VM record using the appropriate repository method or API
	// Since we don't have direct access to db here, we need to create a method in the asset repository
	vmRecord := assetDomain.VMwareVM{
		VMID:         vm.Config.InstanceUuid,
		AssetID:      assetID,
		VMName:       vm.Name,
		Hypervisor:   hypervisor,
		CPUCount:     vm.Config.Hardware.NumCPU,
		MemoryMB:     vm.Config.Hardware.MemoryMB,
		DiskSizeGB:   diskSizeGB,
		PowerState:   powerState,
		LastSyncedAt: time.Now(),
	}

	// Call a method on the asset repository that we need to implement
	return r.storeVMwareVMData(ctx, vmRecord)
}

// Helper method to avoid direct DB access
func (r *VCenterRunner) storeVMwareVMData(ctx context.Context, vmData assetDomain.VMwareVM) error {
	// This is a temporary implementation
	// In a proper implementation, you should add a StoreVMwareVM method to the asset repository interface
	log.Printf("Storing VMware VM data for VM %s", vmData.VMName)

	// For now, just log the data that would be stored
	log.Printf("VM ID: %s, Asset ID: %s, Name: %s", vmData.VMID, vmData.AssetID, vmData.VMName)
	log.Printf("Hypervisor: %s, CPU: %d, Memory: %d MB, Disk: %d GB",
		vmData.Hypervisor, vmData.CPUCount, vmData.MemoryMB, vmData.DiskSizeGB)
	log.Printf("Power State: %s, Last Synced: %v", vmData.PowerState, vmData.LastSyncedAt)

	// In a real implementation, this would call something like:
	// return r.assetRepo.StoreVMwareVM(ctx, vmData)

	return nil
}

// CancelScan cancels a running scan job
func (r *VCenterRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *VCenterRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}
