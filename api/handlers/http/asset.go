package http

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/service"
)

// CreateAsset handles creation of a new asset via HTTP
func CreateAsset(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.CreateAssetRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		resp, err := srv.CreateAsset(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrIPAlreadyExists) {
				return fiber.NewError(fiber.StatusConflict, "IP address already exists")
			}
			if errors.Is(err, service.ErrHostnameAlreadyExists) {
				return fiber.NewError(fiber.StatusConflict, "Hostname already exists")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(resp)
	}
}

// UpdateAsset handles updating an existing asset via HTTP
func UpdateAsset(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.UpdateAssetRequest
		req.Id = c.Params("id")
		if req.Id == "" {
			return fiber.ErrBadRequest
		}

		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		resp, err := srv.UpdateAsset(c.UserContext(), &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrIPAlreadyExists) {
				return fiber.NewError(fiber.StatusConflict, "IP address already exists")
			}
			if errors.Is(err, service.ErrHostnameAlreadyExists) {
				return fiber.NewError(fiber.StatusConflict, "Hostname already exists")
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(resp)
	}
}

// GetAssetByID retrieves a single asset by its ID from URL parameter
func GetAssetByID(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			return fiber.ErrBadRequest
		}

		response, err := srv.GetAsset(c.UserContext(), &pb.GetAssetByIDRequest{
			Id: id,
		})

		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrAssetNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		if response.Asset == nil {
			return fiber.ErrNotFound
		}

		return c.JSON(response)
	}
}

// GetAssets retrieves assets based on filter criteria, pagination, and sorting from URL query parameters
func GetAssets(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.GetAssetsRequest

		// Set pagination parameters
		limit := c.QueryInt("limit", 10)
		req.Limit = int32(limit)

		page := c.QueryInt("page", 0)
		req.Page = int32(page)

		// Extract sorts and filters from query parameters
		queries := c.Queries()
		req.Sort = extractSorts(queries)
		req.Filter = extractAssetFilters(queries)

		response, err := srv.GetAssets(c.UserContext(), &req)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		// Transforming the response to add table names as prefixes and convert nested objects to lists
		transformedResponse := transformGetAssetsResponse(response)
		return c.JSON(transformedResponse)
	}
}

// DeleteAsset deletes a single asset by its ID
func DeleteAsset(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		id := c.Params("id")
		if id == "" {
			return fiber.ErrBadRequest
		}

		// Convert string ID to UUID
		assetUUID, err := uuid.Parse(id)
		if err != nil {
			return fiber.ErrBadRequest
		}

		response, err := srv.DeleteAssets(c.UserContext(), &pb.DeleteAssetsRequest{
			Ids: []string{assetUUID.String()},
		})

		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				return fiber.ErrBadRequest
			}
			if errors.Is(err, service.ErrAssetNotFound) {
				return fiber.ErrNotFound
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}

// DeleteAssets deletes multiple assets by their IDs in the request body
func DeleteAssets(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.DeleteAssetsRequest

		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		if len(req.Ids) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "IDs must not be empty")
		}

		response, err := srv.DeleteAssets(c.UserContext(), &req)

		if err != nil {
			if errors.Is(err, service.ErrInvalidAssetUUID) {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}

// ExportAssets handles the export of assets to CSV format
func ExportAssets(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		var req pb.ExportAssetsRequest
		if err := c.BodyParser(&req); err != nil {
			return fiber.ErrBadRequest
		}

		if req.ExportType == pb.ExportType_SELECTED_COLUMNS && len(req.SelectedColumns) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "selected columns must not be empty for SELECTED_COLUMNS export type")
		}

		csvData, err := srv.ExportAssets(c.UserContext(), &req)
		if err != nil {
			if err == service.ErrInvalidAssetUUID {
				return fiber.ErrBadRequest
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		filename := fmt.Sprintf("asset_export_%s.csv", time.Now().Format("20060102_150405"))

		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Set("Content-Type", "text/csv")

		return c.Send(csvData)
	}
}

// GetDistinctOSNames returns all distinct OS names from assets
func GetDistinctOSNames(svcGetter ServiceGetter[*service.AssetService]) fiber.Handler {
	return func(c *fiber.Ctx) error {
		srv := svcGetter(c.UserContext())

		response, err := srv.GetDistinctOSNames(c.UserContext(), &pb.GetDistinctOSNamesRequest{})
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}

		return c.JSON(response)
	}
}
