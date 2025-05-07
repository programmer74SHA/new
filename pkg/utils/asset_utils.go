package utils

import (
	"strings"
)

// Helper function to split comma-separated values and trim spaces
func SplitAndTrim(value string) []string {
	if value == "" {
		return []string{}
	}

	values := strings.Split(value, ",")
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}
	return values
}

// Helper function to check if filter has any values
func HasFilterValues(value string) bool {
	return strings.TrimSpace(value) != ""
}
