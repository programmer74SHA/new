package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"
)

func CreateScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		var req pb.CreateScannerRequest
		if err := c.BodyParser(&req); err != nil {
			// Log the error for debugging
			context.GetLogger(c.UserContext()).Error("Failed to parse request body", "error", err)
			return fiber.ErrBadRequest
		}

		// Call the service to create the scanner
		response, err := srv.CreateScanner(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.Status(fiber.StatusCreated).JSON(response)
	}
}

func GetScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			log.Printf("Scanner ID is empty")
			return fiber.ErrBadRequest
		}

		log.Printf("Looking up scanner with ID: %s", id)

		response, err := srv.GetScanner(c.UserContext(), &pb.GetScannerRequest{Id: id})

		if err != nil {
			log.Printf("Error retrieving scanner: %v", err)
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}

func UpdateScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		srv := svcGetter(ctx)
		logger := context.GetLogger(ctx)

		// Get scanner ID from URL parameter
		id := c.Params("id")
		if id == "" {
			logger.Error("Scanner ID is empty for update request")
			return fiber.ErrBadRequest
		}

		// Get the raw body
		body := c.Body()

		// Parse the raw request to access the schedule object
		var rawRequest map[string]interface{}
		if err := json.Unmarshal(body, &rawRequest); err != nil {
			logger.Error("Failed to parse raw request", "error", err)
			return fiber.ErrBadRequest
		}

		// Parse the request into the protobuf struct
		var req pb.UpdateScannerRequest
		if err := json.Unmarshal(body, &req); err != nil {
			logger.Error("Failed to parse request into UpdateScannerRequest", "error", err)
			return fiber.ErrBadRequest
		}

		// Set the ID from the path parameter
		req.Id = id

		// Process schedule fields if schedule object exists
		if scheduleObj, ok := rawRequest["schedule"].(map[string]interface{}); ok {
			logger.Info("Processing schedule object for scanner update")
			processScheduleFields(scheduleObj, &req)

			// Log the processed schedule data for debugging
			logger.Info("Processed schedule data",
				"schedule_type", req.ScheduleType,
				"frequency_value", req.FrequencyValue,
				"frequency_unit", req.FrequencyUnit,
				"run_time", req.RunTime,
				"hour", req.Hour,
				"minute", req.Minute,
				"day", req.Day,
				"week", req.Week,
				"month", req.Month)
		} else {
			logger.Info("No schedule object found in request")
		}

		logger.Info("Processing scanner update request", "id", id)

		// Call the service to update the scanner
		response, err := srv.UpdateScanner(ctx, &req)
		if err != nil {
			logger.Error("Failed to update scanner", "id", id, "error", err)

			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			} else if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		logger.Info("Scanner updated successfully", "id", id)
		return c.JSON(response)
	}
}

func processScheduleFields(scheduleObj map[string]interface{}, req *pb.UpdateScannerRequest) {
	// Handle schedule type
	if scheduleType, ok := scheduleObj["schedule_type"].(string); ok && scheduleType != "" {
		req.ScheduleType = scheduleType
	}

	// Handle frequency settings
	if frequencyValue, ok := scheduleObj["frequency_value"].(float64); ok {
		req.FrequencyValue = int64(frequencyValue)
	}
	if frequencyUnit, ok := scheduleObj["frequency_unit"].(string); ok && frequencyUnit != "" {
		req.FrequencyUnit = frequencyUnit
	}

	// Handle run_time
	if runTime, ok := scheduleObj["run_time"].(string); ok && runTime != "" {
		req.RunTime = runTime
	}

	// Handle specific time components
	if month, ok := scheduleObj["month"].(float64); ok {
		req.Month = int64(month)
	}
	if week, ok := scheduleObj["week"].(float64); ok {
		req.Week = int64(week)
	}
	if day, ok := scheduleObj["day"].(float64); ok {
		req.Day = int64(day)
	}
	if hour, ok := scheduleObj["hour"].(float64); ok {
		req.Hour = int64(hour)
	}
	if minute, ok := scheduleObj["minute"].(float64); ok {
		req.Minute = int64(minute)
	}
}

func DeleteScanner(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			return fiber.ErrBadRequest
		}

		_, err := srv.DeleteScanner(c.UserContext(), &pb.DeleteScannerRequest{Id: id})
		if err != nil {
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.Status(fiber.StatusNoContent).Send(nil)
	}
}

func DeleteScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.DeleteScannersRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		if len(req.Ids) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "IDs must not be empty")
		}

		response, err := srv.DeleteScanners(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}

// ListScanners handler with improved status field handling
func ListScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		logger := context.GetLogger(c.UserContext())
		// Extract pagination parameters
		limit := c.QueryInt("limit", 0)
		page := c.QueryInt("page", 0)
		sortField, sortOrder := extractSortParameters(c)
		// Get name filter
		scannerName := c.Query("name", "")
		if scannerName == "" {
			scannerName = c.Query("filter[name]", "")
		}
		// Get scan_type filter
		scanType := c.Query("type", "")
		if scanType == "" {
			scanType = c.Query("filter[scan_type]", "")
			if scanType == "" {
				scanType = c.Query("filter[type]", "")
			}
		}
		// Handle boolean status filter
		statusParam := c.Query("status", c.Query("filter[status]", ""))
		var statusValue bool
		var hasStatusFilter bool
		req := &pb.ListScannersRequest{
			Name:     scannerName,
			ScanType: scanType,
		}
		if statusParam != "" {
			hasStatusFilter = true
			req.HasStatusFilter = true // Set the new field
			if statusParam == "true" || statusParam == "1" {
				statusValue = true
				req.Status = true
			} else if statusParam == "false" || statusParam == "0" {
				statusValue = false
				req.Status = false
			}
			logger.Info("Setting status filter from URL", "status", statusValue)
		}
		logger.Info("Parsing filter parameters from URL query",
			"limit", limit,
			"page", page,
			"sort_field", sortField,
			"sort_order", sortOrder,
			"name", scannerName,
			"scan_type", scanType,
			"status", statusParam,
			"has_status_filter", hasStatusFilter)
		// Call the service method
		response, totalCount, err := srv.ListScanners(
			c.UserContext(),
			req,
			limit,
			page,
			sortField,
			sortOrder,
		)
		if err != nil {
			logger.Error("Failed to list scanners", "error", err)
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		// Process scanner data using a custom struct to ensure field order
		type OrderedScanner struct {
			ScanName  interface{} `json:"scan_name"`
			Type      interface{} `json:"type"`
			Target    string      `json:"target"`
			Status    bool        `json:"status"`
			ID        interface{} `json:"id,omitempty"`
			CreatedAt interface{} `json:"created_at,omitempty"`
			UpdatedAt interface{} `json:"updated_at,omitempty"`
			Domain    interface{} `json:"domain,omitempty"`
			// Add other optional fields as needed
		}

		contents := make([]interface{}, 0)
		for _, scanner := range response.Scanners {
			// Convert scanner to map to access all fields
			scannerBytes, _ := json.Marshal(scanner)
			var scannerMap map[string]interface{}
			json.Unmarshal(scannerBytes, &scannerMap)

			// Create ordered struct
			ordered := OrderedScanner{
				ScanName: scannerMap["name"],
				Type:     scannerMap["scan_type"],
				Target:   formatTargetField(scanner),
				Status:   scanner.Status,
				ID:       scannerMap["id"],
			}

			// Add optional fields if they exist
			if val, ok := scannerMap["created_at"]; ok {
				ordered.CreatedAt = val
			}
			if val, ok := scannerMap["updated_at"]; ok {
				ordered.UpdatedAt = val
			}
			if val, ok := scannerMap["domain"]; ok {
				ordered.Domain = val
			}

			contents = append(contents, ordered)
		}

		// Add status to filter response if it was part of the request
		filterObj := map[string]interface{}{
			"name":      req.Name,
			"scan_type": req.ScanType,
		}
		if hasStatusFilter {
			filterObj["status"] = statusValue
		}
		result := map[string]interface{}{
			"data": map[string]interface{}{
				"contents": contents, // Use our processed scanner data
				"count":    totalCount,
			},
			"scanner": map[string]interface{}{
				"limit": limit,
				"page":  page,
				"sort": []map[string]string{
					{
						"field": mapDBColumnToAPIField(sortField),
						"order": sortOrder,
					},
				},
				"filter": filterObj,
			},
		}
		logger.Info("Returning scanner list", "count", len(contents), "total", totalCount)
		return c.JSON(result)
	}
}

// formatTargetField creates a consolidated target string based on scanner properties and scanner type
func formatTargetField(scanner *pb.Scanner) string {
	// Handle formatting based on scanner type
	switch scanner.ScanType {
	case "NMAP":
		// For NMAP scanners, use Target field to determine formatting
		if scanner.Target == "" {
			return ""
		}
		switch scanner.Target {
		case "IP":
			return scanner.Ip
		case "Network":
			if scanner.Ip != "" && scanner.Subnet > 0 {
				return fmt.Sprintf("%s/%d", scanner.Ip, scanner.Subnet)
			}
		case "Range":
			if scanner.StartIp != "" && scanner.EndIp != "" {
				return fmt.Sprintf("%s to %s", scanner.StartIp, scanner.EndIp)
			}
		}
		return ""
	case "VCENTER":
		// For VCenter scanners, format as IP:Port
		if scanner.Ip != "" {
			if scanner.Port != "" {
				return fmt.Sprintf("%s:%s", scanner.Ip, scanner.Port)
			}
			return scanner.Ip
		}
		return ""
	case "DOMAIN":
		// For Domain scanners, format as Domain (IP:Port)
		if scanner.Domain != "" && scanner.Ip != "" && scanner.Port != "" {
			return fmt.Sprintf("%s (%s:%s)", scanner.Domain, scanner.Ip, scanner.Port)
		} else if scanner.Domain != "" {
			return scanner.Domain
		} else if scanner.Ip != "" {
			if scanner.Port != "" {
				return fmt.Sprintf("%s:%s", scanner.Ip, scanner.Port)
			}
			return scanner.Ip
		}
		return ""
	default:
		return ""
	}
}

func UpdateScannerStatus(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		logger := context.GetLogger(c.UserContext())

		var req pb.UpdateScannerStatusRequest
		if err := c.BodyParser(&req); err != nil {
			logger.Error("Failed to parse request body", "error", err)
			return fiber.ErrBadRequest
		}

		logger.Info("Processing scanner status update request",
			"ids", req.Ids,
			"status", req.Status,
			"filter", req.Filter,
			"exclude", req.Exclude,
			"update_all", req.UpdateAll)

		response, err := srv.UpdateScannerStatus(c.UserContext(), &req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.Status(fiber.StatusOK).JSON(response)
	}
}

// RunScanNow handles HTTP requests to immediately execute a scan for a scanner
func RunScanNow(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		// Get scanner ID from URL parameter
		id := c.Params("id")
		if id == "" {
			log.Printf("Run scan now: Scanner ID is empty")
			return fiber.ErrBadRequest
		}

		log.Printf("Attempting to run immediate scan for scanner with ID: %s", id)

		// Create the request
		req := &pb.RunScanNowRequest{
			ScannerId: id,
		}

		// Call the service to execute the scan
		response, err := srv.RunScanNow(c.UserContext(), req)
		if err != nil {
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !response.Success {
			return fiber.NewError(fiber.StatusInternalServerError, response.ErrorMessage)
		}

		return c.Status(fiber.StatusOK).JSON(response)
	}
}

// extractSortParameters extracts and maps sort parameters from the request
func extractSortParameters(c *fiber.Ctx) (string, string) {
	// Default values
	sortField := "id"
	sortOrder := "desc"

	// Check for legacy format first
	if legacySortField := c.Query("sort_field"); legacySortField != "" {
		sortField = mapAPIFieldToDBColumn(legacySortField)
		sortOrder = c.Query("sort_order", "desc")
		return sortField, sortOrder
	}

	// Check for array format: sort[0][field] and sort[0][order]
	if arraySortField := c.Query("sort[0][field]"); arraySortField != "" {
		sortField = mapAPIFieldToDBColumn(arraySortField)
		sortOrder = c.Query("sort[0][order]", "desc")
		return sortField, sortOrder
	}

	// Return defaults
	return sortField, sortOrder
}

// mapAPIFieldToDBColumn maps API field names to database column names
func mapAPIFieldToDBColumn(apiField string) string {
	fieldMapping := map[string]string{
		"id":         "id",
		"name":       "name",
		"type":       "scan_type", // Maps "type" to "scan_type"
		"status":     "status",
		"created_at": "created_at",
		"updated_at": "updated_at",
		"user_id":    "user_id",
	}

	if dbColumn, exists := fieldMapping[apiField]; exists {
		return dbColumn
	}

	// Default to id if field is not recognized
	return "id"
}

// mapDBColumnToAPIField maps database column names back to API field names for response
func mapDBColumnToAPIField(dbColumn string) string {
	fieldMapping := map[string]string{
		"id":         "id",
		"name":       "name",
		"scan_type":  "type", // Maps "scan_type" back to "type"
		"status":     "status",
		"created_at": "created_at",
		"updated_at": "updated_at",
		"user_id":    "user_id",
	}

	if apiField, exists := fieldMapping[dbColumn]; exists {
		return apiField
	}

	return dbColumn
}
