package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// NmapRunner handles executing Nmap scans
type NmapRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewNmapRunner creates a new Nmap runner with asset repository
func NewNmapRunner(assetRepo assetPort.Repo) *NmapRunner {
	return &NmapRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// ExecuteNmapScan runs an Nmap scan based on scanner configuration
func (r *NmapRunner) ExecuteNmapScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("Starting Nmap scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Build Nmap command based on scanner configuration
	args := []string{"-sS", "-T4", "--top-ports", "1000", "-oX", "-"}

	// Add target based on scan type
	switch scanner.ScanType {
	case scannerDomain.ScannerTypeNmap:
		// Get the Nmap metadata to determine target type
		targetArgs, err := buildNmapTargetArgs(scanner)
		if err != nil {
			log.Printf("Error building target args: %v", err)
			return err
		}
		args = append(args, targetArgs...)
	default:
		return fmt.Errorf("unsupported scanner type for Nmap: %s", scanner.ScanType)
	}

	log.Printf("Executing Nmap command: nmap %s", strings.Join(args, " "))

	// Execute the Nmap command with the cancellable context
	cmd := exec.CommandContext(scanCtx, "nmap", args...)
	output, err := cmd.Output()

	// Check if the context was cancelled
	if scanCtx.Err() == context.Canceled {
		log.Printf("Nmap scan was cancelled for job ID: %d", scanJobID)
		return context.Canceled
	}

	if err != nil {
		log.Printf("Error executing Nmap: %v", err)
		return err
	}

	// Parse the XML output
	var nmapRun NmapRun
	if err := xml.Unmarshal(output, &nmapRun); err != nil {
		log.Printf("Error parsing Nmap XML output: %v", err)
		return err
	}

	// Process and store the results
	return r.processNmapResults(ctx, nmapRun, scanJobID)
}

// CancelScan cancels a running scan job
func (r *NmapRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *NmapRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// buildNmapTargetArgs constructs the target arguments for Nmap based on scanner configuration
func buildNmapTargetArgs(scanner scannerDomain.ScannerDomain) ([]string, error) {
	log.Printf("Building Nmap target args for scanner: %+v", scanner)

	var args []string

	switch scanner.Target {
	case "IP":
		if scanner.IP == "" {
			return nil, fmt.Errorf("IP target specified but no IP address provided")
		}
		args = append(args, scanner.IP)
	case "Network":
		if scanner.IP == "" {
			return nil, fmt.Errorf("Network target specified but no IP address provided")
		}
		cidr := fmt.Sprintf("%s/%d", scanner.IP, scanner.Subnet)
		args = append(args, cidr)
	case "Range":
		if scanner.StartIP == "" || scanner.EndIP == "" {
			return nil, fmt.Errorf("Range target specified but start or end IP missing")
		}

		// Extract only the last octet from the end IP if they share the same subnet
		startIPParts := strings.Split(scanner.StartIP, ".")
		endIPParts := strings.Split(scanner.EndIP, ".")

		// Check if the first three octets are the same
		if len(startIPParts) == 4 && len(endIPParts) == 4 &&
			startIPParts[0] == endIPParts[0] &&
			startIPParts[1] == endIPParts[1] &&
			startIPParts[2] == endIPParts[2] {
			// Use the shorthand notation with just the last octet of the end IP
			targetRange := fmt.Sprintf("%s-%s", scanner.StartIP, endIPParts[3])
			args = append(args, targetRange)
		}
	default:
		return nil, fmt.Errorf("unsupported target type: %s", scanner.Target)
	}

	log.Printf("Built Nmap target args: %v", args)
	return args, nil
}

// processNmapResults parses Nmap results and stores them in the database
func (r *NmapRunner) processNmapResults(ctx context.Context, nmapRun NmapRun, scanJobID int64) error {
	log.Printf("Processing Nmap results for scan job ID: %d", scanJobID)

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue // Skip hosts that are not up
		}

		// Get the IP address
		var ipAddress string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ipAddress = addr.Addr
				break
			}
		}

		if ipAddress == "" {
			log.Printf("No IPv4 address found for host, skipping")
			continue
		}

		// Get hostname if available
		hostname := ipAddress // Default to IP if no hostname
		if len(host.Hostnames.Hostname) > 0 {
			hostname = host.Hostnames.Hostname[0].Name
		}

		// Create new asset with IP in the IPs array
		asset := assetDomain.AssetDomain{
			ID:          uuid.New(),
			Name:        hostname,
			Hostname:    hostname,
			IPs:         []string{ipAddress}, // Use IPs array instead of single IP
			Type:        "Unknown",
			Description: fmt.Sprintf("Discovered by Nmap scan (Job ID: %d)", scanJobID),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Detect OS if available
		if len(host.OS.OSMatches) > 0 && len(host.OS.OSMatches[0].OSClasses) > 0 {
			osClass := host.OS.OSMatches[0].OSClasses[0]
			asset.OSName = osClass.OSFamily
			if osClass.OSGen != "" {
				asset.OSVersion = osClass.OSGen
			}
		}

		// Store the asset
		assetID, err := r.assetRepo.Create(ctx, asset)
		if err != nil {
			log.Printf("Error creating asset: %v", err)
			continue
		}

		// Link the asset to the scan job
		err = r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
		if err != nil {
			log.Printf("Error linking asset to scan job: %v", err)
		}

		log.Printf("Successfully processed host %s (Asset ID: %s)", ipAddress, assetID)
	}

	return nil
}

// NmapRun represents the root element of Nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a host in Nmap XML output
type Host struct {
	XMLName   xml.Name  `xml:"host"`
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr,omitempty"`
				Version string `xml:"version,attr,omitempty"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
	OS struct {
		OSMatches []struct {
			Name      string `xml:"name,attr"`
			Accuracy  string `xml:"accuracy,attr"`
			OSClasses []struct {
				Type     string `xml:"type,attr"`
				Vendor   string `xml:"vendor,attr"`
				OSFamily string `xml:"osfamily,attr"`
				OSGen    string `xml:"osgen,attr"`
			} `xml:"osclass"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

// Status represents the status of a host
type Status struct {
	State string `xml:"state,attr"`
}

// Address represents an address of a host
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
