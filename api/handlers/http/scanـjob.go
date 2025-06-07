package http

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
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

		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}

		res, err := srv.GetJobByID(c.UserContext(), &pb.GetJobByIDRequest{Id: int64(id)})
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

		// Get scan job ID from URL parameter
		id := c.Params("id")
		if id == "" {
			log.Printf("Cancel scan job: Scan job ID is empty")
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
			if errors.Is(err, service.ErrScanJobNotFound) {
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

// DiffJobs compares two scan jobs and returns the differences in assets
func DiffJobs(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.DiffJobsRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		// Validate that both job IDs are provided
		if req.GetNewerJobId() == 0 || req.GetOlderJobId() == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "Both newer_job_id and older_job_id must be provided")
		}

		// Set pagination parameters
		limit := c.QueryInt("limit", 5)
		req.Limit = int32(limit)

		page := c.QueryInt("page", 0)
		req.Page = int32(page)

		// Validate pagination parameters
		if req.Limit < 1 {
			req.Limit = 5
		}
		if req.Page < 0 {
			req.Page = 0
		}

		res, err := srv.DiffJobs(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScanJobUUID) {
				return fiber.NewError(fiber.StatusBadRequest, "Invalid job ID format")
			}
			if errors.Is(err, service.ErrScanJobNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "One or both scan jobs not found")
			}
			if errors.Is(err, service.ErrJobNotComplete) {
				return fiber.NewError(fiber.StatusBadRequest, "Both jobs must have 'Completed' status for diffing")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(res)
	}
}

// ExportJobDiff exports the diff between two scan jobs as a CSV file
func ExportJobDiff(svcGetter ServiceGetter[*service.ScanJobService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.ExportJobDiffRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		// Validate that both job IDs are provided
		if req.GetNewerJobId() == 0 || req.GetOlderJobId() == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "Both newer_job_id and older_job_id must be provided")
		}

		csvData, err := srv.ExportJobDiff(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidScanJobUUID) {
				return fiber.NewError(fiber.StatusBadRequest, "Invalid job ID format")
			}
			if errors.Is(err, service.ErrScanJobNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "One or both scan jobs not found")
			}
			if errors.Is(err, service.ErrJobNotComplete) {
				return fiber.NewError(fiber.StatusBadRequest, "Both jobs must have 'Completed' status for diffing")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		filename := fmt.Sprintf("job_diff_export_%s.csv", time.Now().Format("20060102_150405"))

		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Set("Content-Type", "text/csv")

		return c.Send(csvData)
	}
}
