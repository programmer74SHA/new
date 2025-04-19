package domain

import "time"

// VMwareVM represents VMware virtual machine data
type VMwareVM struct {
	VMID         string    // Unique identifier from vCenter
	AssetID      string    // Related asset ID
	VMName       string    // VM name
	Hypervisor   string    // ESXi/vSphere version info
	CPUCount     int32     // Number of CPUs
	MemoryMB     int32     // Memory in MB
	DiskSizeGB   int       // Total disk size in GB
	PowerState   string    // On, Off, Suspended
	LastSyncedAt time.Time // When the VM was last synchronized
}
