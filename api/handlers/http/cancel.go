package http

import (
	"errors"
	"log"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scheduler"
)

// CancelScanJob handles HTTP requests to cancel running scan jobs
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
