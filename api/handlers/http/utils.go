package http

import (
	"context"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	jwt2 "github.com/golang-jwt/jwt/v5"
	"gitlab.apk-group.net/siem/backend/asset-discovery/api/pb"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/jwt"
)

func userClaims(ctx *fiber.Ctx) *jwt.UserClaims {
	if u := ctx.Locals("user"); u != nil {
		userClaims, ok := u.(*jwt2.Token).Claims.(*jwt.UserClaims)
		if ok {
			return userClaims
		}
	}

	return nil
}

type ServiceGetter[T any] func(context.Context) T

// extractSorts processes the sort parameters from fiber.Ctx queries
func extractSorts(queries map[string]string) []*pb.SortField {
	var sorts []*pb.SortField

	for key, value := range queries {
		if !strings.HasPrefix(key, "sort[") || !strings.Contains(key, "][") {
			continue
		}

		indexEnd := strings.Index(key, "][")
		if indexEnd <= 5 {
			continue
		}

		indexStr := key[5:indexEnd]
		fieldType := key[indexEnd+2 : len(key)-1]

		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			continue
		}

		for len(sorts) <= index {
			sorts = append(sorts, &pb.SortField{
				Field: "created_at",
				Order: "desc",
			})
		}

		if fieldType == "field" {
			sorts[index].Field = value
		} else if fieldType == "order" && (value == "asc" || value == "desc") {
			sorts[index].Order = value
		}
	}

	return sorts
}

// extractAssetFilters processes the asset filter parameters from fiber.Ctx queries
func extractAssetFilters(queries map[string]string) *pb.Filter {
	filter := &pb.Filter{}

	for key, value := range queries {
		if !strings.HasPrefix(key, "filter[") || !strings.HasSuffix(key, "]") || len(key) <= 8 {
			continue
		}

		fieldName := key[7 : len(key)-1]

		switch fieldName {
		case "name":
			filter.Name = value
		case "domain":
			filter.Domain = value
		case "hostname":
			filter.Hostname = value
		case "os_name":
			filter.OsName = value
		case "os_version":
			filter.OsVersion = value
		case "type":
			filter.Type = value
		case "ip":
			filter.Ip = value
		}
	}

	return filter
}

// extractScanJobFilters processes the scan jobs filter parameters from fiber.Ctx queries
func extractScanJobFilters(queries map[string]string) *pb.ScanJobFilter {
	filter := &pb.ScanJobFilter{}

	for key, value := range queries {
		if !strings.HasPrefix(key, "filter[") || !strings.HasSuffix(key, "]") || len(key) <= 8 {
			continue
		}

		fieldName := key[7 : len(key)-1]

		switch fieldName {
		case "name":
			filter.Name = value
		case "status":
			filter.Status = value
		case "start_time_from":
			filter.StartTimeFrom = value
		case "start_time_to":
			filter.StartTimeTo = value
		case "type":
			filter.Type = value
		}
	}

	return filter
}
