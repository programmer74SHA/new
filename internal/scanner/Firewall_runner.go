package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	assetDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/domain"
	assetPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/asset/port"
	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// FortiGate API response structures
type FortigateResponse struct {
	Results []json.RawMessage `json:"results"`
	Status  string            `json:"status"`
}

type Zone struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Interface   []ZoneInterface `json:"interface"`
}

type ZoneInterface struct {
	InterfaceName string `json:"interface-name"`
	Name          string `json:"name"`
}

type Interface struct {
	Name        string        `json:"name"`
	IP          string        `json:"ip"`
	Status      string        `json:"status"`
	Description string        `json:"description"`
	MTU         int           `json:"mtu"`
	Speed       string        `json:"speed"`
	Duplex      string        `json:"duplex"`
	Type        string        `json:"type"`
	VDOM        string        `json:"vdom"`
	Mode        string        `json:"mode"`
	Role        string        `json:"role"`
	MacAddr     string        `json:"macaddr"`
	Allowaccess []string      `json:"allowaccess"`
	SecondaryIP []SecondaryIP `json:"secondaryip"`
}

type SecondaryIP struct {
	ID          int      `json:"id"`
	IP          string   `json:"ip"`
	Allowaccess []string `json:"allowaccess"`
}

type Policy struct {
	PolicyID int               `json:"policyid"`
	Name     string            `json:"name"`
	SrcIntf  []PolicyInterface `json:"srcintf"`
	DstIntf  []PolicyInterface `json:"dstintf"`
	SrcAddr  []Address         `json:"srcaddr"`
	DstAddr  []Address         `json:"dstaddr"`
	Service  []Service         `json:"service"`
	Action   string            `json:"action"`
	Status   string            `json:"status"`
	Schedule string            `json:"schedule"`
}

type PolicyInterface struct {
	Name string `json:"name"`
}

type Service struct {
	Name string `json:"name"`
}

// FirewallRunner handles executing firewall scans
type FirewallRunner struct {
	assetRepo     assetPort.Repo
	cancelManager *ScanCancelManager
}

// NewFirewallRunner creates a new firewall runner with asset repository
func NewFirewallRunner(assetRepo assetPort.Repo) *FirewallRunner {
	return &FirewallRunner{
		assetRepo:     assetRepo,
		cancelManager: NewScanCancelManager(),
	}
}

// ExecuteFirewallScan runs a firewall scan and stores discovered interfaces as assets
func (r *FirewallRunner) ExecuteFirewallScan(ctx context.Context, scanner scannerDomain.ScannerDomain, scanJobID int64) error {
	log.Printf("[FirewallScanner] Starting firewall scan for scanner ID: %d, job ID: %d", scanner.ID, scanJobID)
	log.Printf("[FirewallScanner] Scanner details: IP=%s, Port=%s, API Key length=%d",
		scanner.IP, scanner.Port, len(scanner.ApiKey))

	// Create a cancellable context
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Register this scan with the cancel manager
	r.cancelManager.RegisterScan(scanJobID, cancel)
	defer r.cancelManager.UnregisterScan(scanJobID)

	// Determine port to use (default to 443 for HTTPS)
	port := "443"
	if scanner.Port != "" {
		port = scanner.Port
	}

	// Validate API key
	if scanner.ApiKey == "" {
		log.Printf("[FirewallScanner] API key is empty")
		return fmt.Errorf("API key is required for firewall scanner")
	}

	// Create FortiGate client
	client := r.createFortigateClient(scanner.IP, port, scanner.ApiKey)

	// Test connection first with multiple authentication methods
	if err := r.testConnectionWithFallback(scanCtx, client, scanner.ApiKey); err != nil {
		log.Printf("[FirewallScanner] All connection tests failed: %v", err)
		return fmt.Errorf("FortiGate connection failed: %w", err)
	}

	log.Printf("[FirewallScanner] Successfully connected to FortiGate")

	// Create firewall extractor
	extractor := NewFortigateExtractor(client, scanner, scanJobID)

	// Load all data from FortiGate
	if err := extractor.LoadAllData(scanCtx); err != nil {
		log.Printf("[FirewallScanner] Error loading firewall data: %v", err)
		return fmt.Errorf("failed to load firewall data: %w", err)
	}

	// Process and store data as assets
	return r.processFirewallDataAsAssets(scanCtx, extractor, scanJobID)
}

// FortigateClient represents a FortiGate API client
type FortigateClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	authMethod string // Track which auth method works
}

// createFortigateClient creates an HTTP client configured for FortiGate API
func (r *FirewallRunner) createFortigateClient(ip, port, apiKey string) *FortigateClient {
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: false,
		IdleConnTimeout:    30 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	baseURL := fmt.Sprintf("https://%s:%s/api/v2/cmdb", ip, port)

	return &FortigateClient{
		httpClient: client,
		baseURL:    baseURL,
		apiKey:     apiKey,
		authMethod: "bearer", 
	}
}

// testConnectionWithFallback tests different authentication methods
func (r *FirewallRunner) testConnectionWithFallback(ctx context.Context, client *FortigateClient, apiKey string) error {
	log.Printf("[FirewallScanner] Testing connection with API key: %s...", maskAPIKey(apiKey))

	// Test different authentication methods
	authMethods := []struct {
		name   string
		method string
	}{
		{"Bearer Token", "bearer"},
		{"API Key Header", "apikey"},
		{"Query Parameter", "query"},
	}

	var lastErr error

	for _, auth := range authMethods {
		log.Printf("[FirewallScanner] Trying authentication method: %s", auth.name)
		client.authMethod = auth.method

		err := r.testConnection(ctx, client)
		if err == nil {
			log.Printf("[FirewallScanner] Successfully authenticated using: %s", auth.name)
			return nil
		}

		log.Printf("[FirewallScanner] Authentication method %s failed: %v", auth.name, err)
		lastErr = err
	}

	return fmt.Errorf("all authentication methods failed, last error: %w", lastErr)
}

// testConnection tests the connection to FortiGate
func (r *FirewallRunner) testConnection(ctx context.Context, client *FortigateClient) error {
	// Try to fetch a simple endpoint to test connectivity
	_, err := client.fetchData(ctx, "system/interface")
	if err != nil {
		return fmt.Errorf("FortiGate API test failed: %w", err)
	}
	return nil
}

// fetchData makes a generic API call to FortiGate with flexible authentication
func (fg *FortigateClient) fetchData(ctx context.Context, endpoint string) ([]json.RawMessage, error) {
	url := fmt.Sprintf("%s/%s", fg.baseURL, endpoint)

	// Add API key as query parameter for query method
	if fg.authMethod == "query" {
		if strings.Contains(url, "?") {
			url += "&access_token=" + fg.apiKey
		} else {
			url += "?access_token=" + fg.apiKey
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set authentication header based on method
	switch fg.authMethod {
	case "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", fg.apiKey))
	case "apikey":
		req.Header.Set("Authorization", fmt.Sprintf("Api-Key %s", fg.apiKey))
		// Also try X-API-Key header which some FortiGate versions use
		req.Header.Set("X-API-Key", fg.apiKey)
	case "query":
		// API key already added to URL, no header needed
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AssetDiscovery/1.0")

	resp, err := fg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection error fetching %s: %v", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		// Check if it's an HTML error page (common with auth failures)
		if strings.Contains(string(body), "<html>") || strings.Contains(string(body), "<!DOCTYPE") {
			return nil, fmt.Errorf("error fetching %s: %d - Authentication failed (received HTML error page)", endpoint, resp.StatusCode)
		}

		return nil, fmt.Errorf("error fetching %s: %d - %s", endpoint, resp.StatusCode, string(body))
	}

	var response FortigateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("[FirewallScanner] Failed to unmarshal response: %v", err)
		return nil, err
	}

	if response.Status != "success" && response.Status != "" {
		return nil, fmt.Errorf("FortiGate API returned status: %s", response.Status)
	}

	return response.Results, nil
}

// FortigateExtractor handles extracting and storing FortiGate data
type FortigateExtractor struct {
	client     *FortigateClient
	scanner    scannerDomain.ScannerDomain
	scanJobID  int64
	zones      []Zone
	interfaces []Interface
	policies   []Policy
	addresses  []Address
}

// NewFortigateExtractor creates a new FortiGate data extractor
func NewFortigateExtractor(client *FortigateClient, scanner scannerDomain.ScannerDomain, scanJobID int64) *FortigateExtractor {
	return &FortigateExtractor{
		client:    client,
		scanner:   scanner,
		scanJobID: scanJobID,
	}
}

// LoadAllData fetches all relevant data from FortiGate
func (fe *FortigateExtractor) LoadAllData(ctx context.Context) error {
	log.Println("[FirewallScanner] Fetching data from FortiGate...")

	// Fetch zones
	zonesData, err := fe.client.fetchData(ctx, "system/zone")
	if err != nil {
		log.Printf("[FirewallScanner] Error fetching zones: %v", err)
	} else {
		for i, zoneData := range zonesData {
			var zone Zone
			if err := json.Unmarshal(zoneData, &zone); err != nil {
				log.Printf("[FirewallScanner] Failed to unmarshal zone %d: %v", i, err)
				continue
			}
			fe.zones = append(fe.zones, zone)
		}
	}

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Fetch interfaces
	interfacesData, err := fe.client.fetchData(ctx, "system/interface")
	if err != nil {
		log.Printf("[FirewallScanner] Error fetching interfaces: %v", err)
	} else {
		for i, intfData := range interfacesData {
			var intf Interface
			if err := json.Unmarshal(intfData, &intf); err != nil {
				log.Printf("[FirewallScanner] Failed to unmarshal interface %d: %v", i, err)
				// Try to parse as generic map to extract basic info
				intf = fe.parseGenericInterface(intfData, i)
				if intf.Name == "" {
					continue
				}
			}
			fe.interfaces = append(fe.interfaces, intf)
		}
	}

	// Check for cancellation
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}

	// Fetch policies
	policiesData, err := fe.client.fetchData(ctx, "firewall/policy")
	if err != nil {
		log.Printf("[FirewallScanner] Error fetching policies: %v", err)
	} else {
		for _, policyData := range policiesData {
			var policy Policy
			if err := json.Unmarshal(policyData, &policy); err != nil {
				log.Printf("[FirewallScanner] Failed to unmarshal policy: %v", err)
				continue
			}
			fe.policies = append(fe.policies, policy)
		}
	}

	// Fetch addresses
	addressesData, err := fe.client.fetchData(ctx, "firewall/address")
	if err != nil {
		log.Printf("[FirewallScanner] Error fetching addresses: %v", err)
	} else {
		for _, addrData := range addressesData {
			var addr Address
			if err := json.Unmarshal(addrData, &addr); err != nil {
				log.Printf("[FirewallScanner] Failed to unmarshal address: %v", err)
				continue
			}
			fe.addresses = append(fe.addresses, addr)
		}
	}

	log.Printf("[FirewallScanner] Loaded: %d zones, %d interfaces, %d policies, %d addresses",
		len(fe.zones), len(fe.interfaces), len(fe.policies), len(fe.addresses))

	return nil
}

// parseGenericInterface parses interface data from a generic map
func (fe *FortigateExtractor) parseGenericInterface(intfData json.RawMessage, index int) Interface {
	var genericIntf map[string]interface{}
	if err := json.Unmarshal(intfData, &genericIntf); err != nil {
		return Interface{}
	}

	intf := Interface{}

	// Extract basic fields
	if name, ok := genericIntf["name"].(string); ok {
		intf.Name = name
	}
	if ip, ok := genericIntf["ip"].(string); ok {
		intf.IP = ip
	}
	if status, ok := genericIntf["status"].(string); ok {
		intf.Status = status
	}
	if desc, ok := genericIntf["description"].(string); ok {
		intf.Description = desc
	}
	if mtu, ok := genericIntf["mtu"].(float64); ok {
		intf.MTU = int(mtu)
	}
	if speed, ok := genericIntf["speed"].(string); ok {
		intf.Speed = speed
	}
	if duplex, ok := genericIntf["duplex"].(string); ok {
		intf.Duplex = duplex
	}
	if ifType, ok := genericIntf["type"].(string); ok {
		intf.Type = ifType
	}
	if vdom, ok := genericIntf["vdom"].(string); ok {
		intf.VDOM = vdom
	}
	if mode, ok := genericIntf["mode"].(string); ok {
		intf.Mode = mode
	}
	if role, ok := genericIntf["role"].(string); ok {
		intf.Role = role
	}
	if macaddr, ok := genericIntf["macaddr"].(string); ok {
		intf.MacAddr = macaddr
	}

	// Parse allowaccess
	if allowaccess, ok := genericIntf["allowaccess"].([]interface{}); ok {
		for _, access := range allowaccess {
			if accessStr, ok := access.(string); ok {
				intf.Allowaccess = append(intf.Allowaccess, accessStr)
			} else if accessMap, ok := access.(map[string]interface{}); ok {
				if name, ok := accessMap["name"].(string); ok {
					intf.Allowaccess = append(intf.Allowaccess, name)
				}
			}
		}
	}

	// Parse secondary IPs
	if secondaryips, ok := genericIntf["secondaryip"].([]interface{}); ok {
		for _, secIP := range secondaryips {
			if secIPMap, ok := secIP.(map[string]interface{}); ok {
				var secIPStruct SecondaryIP
				if id, ok := secIPMap["id"].(float64); ok {
					secIPStruct.ID = int(id)
				}
				if ip, ok := secIPMap["ip"].(string); ok {
					secIPStruct.IP = ip
				}
				intf.SecondaryIP = append(intf.SecondaryIP, secIPStruct)
			}
		}
	}

	return intf
}

// processFirewallDataAsAssets converts firewall interfaces to assets and stores them
func (r *FirewallRunner) processFirewallDataAsAssets(ctx context.Context, extractor *FortigateExtractor, scanJobID int64) error {
	log.Printf("[FirewallScanner] Processing firewall data as assets for job ID: %d", scanJobID)

	totalAssets := 0
	assetsWithIPs := 0

	// Process interfaces as network assets
	for i, intf := range extractor.interfaces {
		// Check for cancellation periodically
		if i%10 == 0 && ctx.Err() == context.Canceled {
			log.Printf("[FirewallScanner] Firewall scan was cancelled during interface processing for job ID: %d", scanJobID)
			return context.Canceled
		}

		// Skip interfaces without names
		if intf.Name == "" {
			continue
		}

		// Create asset for this interface
		asset := r.createAssetFromInterface(intf, extractor.scanner.IP, scanJobID)

		// Store the asset
		log.Printf("[FirewallScanner] Creating asset for interface: %s", intf.Name)
		assetID, err := r.assetRepo.Create(ctx, asset)
		if err != nil {
			log.Printf("[FirewallScanner] Error creating asset for interface %s: %v", intf.Name, err)
			continue
		}

		// Link the asset to the scan job
		err = r.assetRepo.LinkAssetToScanJob(ctx, assetID, scanJobID)
		if err != nil {
			log.Printf("[FirewallScanner] Error linking asset to scan job: %v", err)
			continue
		}

		log.Printf("[FirewallScanner] Successfully processed interface %s (Asset ID: %s)", intf.Name, assetID)
		totalAssets++

		if len(asset.AssetIPs) > 0 {
			assetsWithIPs++
		}
	}

	log.Printf("[FirewallScanner] Completed processing firewall data. Created %d assets, %d with IP addresses",
		totalAssets, assetsWithIPs)
	return nil
}

// createAssetFromInterface creates an asset from a firewall interface
func (r *FirewallRunner) createAssetFromInterface(intf Interface, firewallIP string, scanJobID int64) assetDomain.AssetDomain {
	// Create asset ID
	assetID := uuid.New()

	// Create asset name
	assetName := fmt.Sprintf("%s-%s", firewallIP, intf.Name)
	if intf.Description != "" {
		assetName = fmt.Sprintf("%s (%s)", assetName, intf.Description)
	}

	// Create asset description
	description := fmt.Sprintf("Firewall interface discovered by FortiGate scan (Job ID: %d). Type: %s, Status: %s",
		scanJobID, intf.Type, intf.Status)

	if intf.VDOM != "" {
		description += fmt.Sprintf(", VDOM: %s", intf.VDOM)
	}
	if intf.Role != "" {
		description += fmt.Sprintf(", Role: %s", intf.Role)
	}

	// Create base asset
	asset := assetDomain.AssetDomain{
		ID:          assetID,
		Name:        assetName,
		Hostname:    intf.Name,
		Type:        "Network Interface",
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AssetIPs:    make([]assetDomain.AssetIP, 0),
	}

	// Extract and add IP addresses
	if intf.IP != "" && intf.IP != "0.0.0.0 0.0.0.0" && intf.IP != "0.0.0.0" {
		// Parse primary IP
		ip, _ := r.parseIPNetmask(intf.IP)
		if ip != "" && r.isValidIPFormat(ip) {
			macAddress := intf.MacAddr
			if macAddress == "" {
				macAddress = "Unknown"
			}

			asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
				AssetID:    assetID.String(),
				IP:         ip,
				MACAddress: macAddress,
			})
			log.Printf("[FirewallScanner] Added primary IP %s with MAC %s for interface %s", ip, macAddress, intf.Name)
		}
	}

	// Add secondary IPs
	for _, secIP := range intf.SecondaryIP {
		if secIP.IP != "" && secIP.IP != "0.0.0.0 0.0.0.0" && secIP.IP != "0.0.0.0" {
			ip, _ := r.parseIPNetmask(secIP.IP)
			if ip != "" && r.isValidIPFormat(ip) {
				macAddress := intf.MacAddr
				if macAddress == "" {
					macAddress = "Unknown"
				}

				asset.AssetIPs = append(asset.AssetIPs, assetDomain.AssetIP{
					AssetID:    assetID.String(),
					IP:         ip,
					MACAddress: macAddress,
				})
				log.Printf("[FirewallScanner] Added secondary IP %s for interface %s", ip, intf.Name)
			}
		}
	}

	return asset
}

// parseIPNetmask parses IP and netmask from FortiGate format
func (r *FirewallRunner) parseIPNetmask(ipString string) (string, string) {
	if ipString == "" || ipString == "0.0.0.0 0.0.0.0" {
		return "", ""
	}

	parts := strings.Fields(ipString)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return ipString, ""
}

// isValidIPFormat validates if a string is a valid IPv4 address format
func (r *FirewallRunner) isValidIPFormat(ip string) bool {
	// Skip empty IPs
	if ip == "" {
		return false
	}

	// Parse IP to validate format
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if it's IPv4
	if parsedIP.To4() == nil {
		return false
	}

	return true
}

// CancelScan cancels a running scan job
func (r *FirewallRunner) CancelScan(jobID int64) bool {
	return r.cancelManager.CancelScan(jobID)
}

// StatusScan checks if a scan job is currently running
func (r *FirewallRunner) StatusScan(jobID int64) bool {
	return r.cancelManager.HasActiveScan(jobID)
}

// maskAPIKey masks an API key for logging
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "****"
	}
	return apiKey[:4] + "****"
}
