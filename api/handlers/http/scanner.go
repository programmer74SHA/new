package http

import (
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

func ListScanners(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())
		logger := context.GetLogger(c.UserContext())

		// Extract pagination parameters from query params
		limit := c.QueryInt("limit", 0)
		page := c.QueryInt("page", 0)
		sortField := c.Query("sort_field", "name")
		sortOrder := c.Query("sort_order", "asc")

		// Support for frontend grid component using array-style query params
		// Check if there are sort[0][field] and sort[0][order] parameters
		if sortFromArr := c.Query("sort[0][field]"); sortFromArr != "" {
			sortField = sortFromArr
			sortOrder = c.Query("sort[0][order]", "asc")
		}

		// Get name filter from standard and bracket notation
		scannerName := c.Query("name", "")
		if scannerName == "" {
			scannerName = c.Query("filter[name]", "")
		}

		// Get scan_type filter from standard and bracket notation
		scanType := c.Query("type", "")
		if scanType == "" {
			scanType = c.Query("filter[scan_type]", "")
			if scanType == "" {
				// Also try scan_type in bracket notation
				scanType = c.Query("filter[type]", "")
			}
		}

		logger.Info("Parsing filter parameters from URL query",
			"limit", limit,
			"page", page,
			"sort_field", sortField,
			"sort_order", sortOrder,
			"name", scannerName,
			"scan_type", scanType)

		// Build filter with the extracted values
		req := &pb.ListScannersRequest{
			Name:     scannerName,
			ScanType: scanType,
		}

		// Handle boolean status filter
		StatusParam := c.Query("status", c.Query("filter[status]", ""))
		if StatusParam != "" {
			Status := false
			// Convert string to boolean
			if StatusParam == "true" || StatusParam == "1" {
				Status = true
				req.Status = true
			} else if StatusParam == "false" || StatusParam == "0" {
				Status = false
				req.Status = false
			}
			// Log the status filter
			logger.Info("Setting status filter from URL", "status", Status)
		}

		// Log the complete request
		logger.Info("Filter request",
			"name", req.Name,
			"scan_type", req.ScanType,
			"status", req.Status)

		// Call the enhanced service method
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

		// Format the response to match the desired structure
		result := map[string]interface{}{
			"data": map[string]interface{}{
				"contents": response.Scanners,
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
				"filter": map[string]interface{}{
					"name":      req.Name,
					"scan_type": req.ScanType,
					"status":    req.Status,
				},
			},
		}

		logger.Info("Returning scanner list", "count", len(response.Scanners), "total", totalCount)
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
