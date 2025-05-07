package http

import (
	"errors"
	"log"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler"
)

// GetScanJobs retrieves scan jobs based on filter, pagination, and sorting
func GetScanJobs(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.GetJobsRequest

		// Set pagination parameters
		limit := c.QueryInt("limit", 10)
		req.Limit = int32(limit)

		page := c.QueryInt("page", 0)
		req.Page = int32(page)

		if req.Limit < 1 {
			req.Limit = 10
		}
		if req.Page < 0 {
			req.Page = 0
		}

		// Extract sorts and filters from query parameters
		queries := c.Queries()
		req.Sort = extractSorts(queries)
		req.Filter = extractScanJobFilters(queries)

		res, err := srv.GetJobs(c.UserContext(), &req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		return c.JSON(res)
	}
}

// GetScanJobByID retrieves a single scan job by its ID
func GetScanJobByID(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			return fiber.ErrBadRequest
		}

		res, err := srv.GetJobByID(c.UserContext(), &pb.GetJobByIDRequest{Id: id})
		if err != nil {
			if errors.Is(err, service.ErrInvalidScanJobUUID) {
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrScanJobNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(res)
	}
}

func CancelScanJob(svcGetter ServiceGetter[*service.ScannerService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		// Get job ID from URL parameter
		id := c.Params("id")
		if id == "" {
			log.Printf("Cancel scan job: Job ID is empty")
			return fiber.ErrBadRequest
		}

		log.Printf("Attempting to cancel scan job with ID: %s", id)

		// Create the request
		req := &pb.CancelScanJobRequest{
			Id: id,
		}

		// Call the service to cancel the scan job
		response, err := srv.CancelScanJob(c.UserContext(), req)
		if err != nil {
			if errors.Is(err, scheduler.ErrScanJobNotRunning) {
				return fiber.NewError(fiber.StatusNotFound, "Scan job is not running")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if !response.Success {
			return fiber.NewError(fiber.StatusInternalServerError, response.ErrorMessage)
		}

		return c.Status(fiber.StatusOK).JSON(response)
	}
}
