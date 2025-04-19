package http

import (
	"encoding/json"
	"errors"
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
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			return fiber.ErrBadRequest
		}

		var req pb.UpdateScannerRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		req.Id = id

		response, err := srv.UpdateScanner(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrScannerNotFound) {
				return fiber.ErrNotFound
			} else if errors.Is(err, service.ErrInvalidScannerInput) {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
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

		_, err := srv.DeleteScanners(c.UserContext(), &req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.Status(fiber.StatusNoContent).Send(nil)
	}
}

type ListScannersBodyRequest struct {
	Limit  int                    `json:"limit"`
	Page   int                    `json:"page"`
	Sort   []map[string]string    `json:"sort"`
	Filter map[string]interface{} `json:"filter"`
}

// ListScanners handler with improved status field handling
func ListScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		logger := context.GetLogger(c.UserContext())

		// Extract pagination parameters
		limit := c.QueryInt("limit", 0)
		page := c.QueryInt("page", 0)
		sortField := c.Query("sort_field", "name")
		sortOrder := c.Query("sort_order", "asc")

		if sortFromArr := c.Query("sort[0][field]"); sortFromArr != "" {
			sortField = sortFromArr
			sortOrder = c.Query("sort[0][order]", "asc")
		}

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

		// Process scanner data to ensure status is included
		var contents []map[string]interface{}
		for _, scanner := range response.Scanners {
			// Convert scanner to map to ensure all fields are preserved
			scannerBytes, _ := json.Marshal(scanner)
			var scannerMap map[string]interface{}
			json.Unmarshal(scannerBytes, &scannerMap)

			// Explicitly ensure status is included, even if false
			scannerMap["status"] = scanner.Status

			contents = append(contents, scannerMap)
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
						"field": sortField,
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

func BatchUpdateScannersEnabled(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.BatchUpdateScannersEnabledRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		_, err := srv.BatchUpdateScannersEnabled(c.UserContext(), &req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.Status(fiber.StatusNoContent).Send(nil)
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
