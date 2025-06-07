package mapper

import (
	"time"
)

// --- Helper Functions ---

func ptrToString(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}

func ptrToTime(p *time.Time) time.Time {
	if p != nil {
		return *p
	}
	return time.Time{}
}
