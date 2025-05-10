package scheduler

import (
	"log"
	"time"

	scannerDomain "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
)

// CalculateNextRunTime determines when the next scan should run based on the schedule configuration
func CalculateNextRunTime(schedule scannerDomain.Schedule, from time.Time) time.Time {
	log.Printf("Calculating next run time from %v with frequency %d %s",
		from, schedule.FrequencyValue, schedule.FrequencyUnit)

	// For minute frequencies, simply add the duration
	if schedule.FrequencyUnit == "minute" {
		nextRun := from.Add(time.Duration(schedule.FrequencyValue) * time.Minute)
		log.Printf("Added %d minutes to %v, result: %v", schedule.FrequencyValue, from, nextRun)
		return nextRun
	}

	// For hour frequencies with a specific minute set
	if schedule.FrequencyUnit == "hour" && schedule.Minute >= 0 && schedule.Minute < 60 {
		// Calculate the next occurrence at the specified minute
		nextRun := time.Date(
			from.Year(),
			from.Month(),
			from.Day(),
			from.Hour(),
			int(schedule.Minute),
			0, 0,
			from.Location(),
		)

		// If we've already passed this minute in the current hour, move to the next hour
		if !nextRun.After(from) {
			nextRun = nextRun.Add(time.Duration(schedule.FrequencyValue) * time.Hour)
		}

		log.Printf("Calculated hourly run at minute %d: %v", schedule.Minute, nextRun)
		return nextRun
	}

	// For hour frequencies without a specific minute
	if schedule.FrequencyUnit == "hour" {
		nextRun := from.Add(time.Duration(schedule.FrequencyValue) * time.Hour)
		log.Printf("Added %d hours to %v, result: %v", schedule.FrequencyValue, from, nextRun)
		return nextRun
	}

	var nextRun time.Time

	// For day/week/month frequencies with specific hour and minute
	if schedule.Hour >= 0 && schedule.Hour < 24 && schedule.Minute >= 0 && schedule.Minute < 60 {
		nextRun = time.Date(
			from.Year(),
			from.Month(),
			from.Day(),
			int(schedule.Hour),
			int(schedule.Minute),
			0, 0,
			from.Location(),
		)

		// If this time has already passed today, move to the next occurrence
		if !nextRun.After(from) {
			switch schedule.FrequencyUnit {
			case "day":
				nextRun = nextRun.AddDate(0, 0, int(schedule.FrequencyValue))
			case "week":
				nextRun = nextRun.AddDate(0, 0, int(schedule.FrequencyValue)*7)
			case "month":
				nextRun = nextRun.AddDate(0, int(schedule.FrequencyValue), 0)
			}
		}
	} else {
		// Handle frequency-based schedules without specific times
		switch schedule.FrequencyUnit {
		case "day":
			nextRun = from.AddDate(0, 0, int(schedule.FrequencyValue))
		case "week":
			nextRun = from.AddDate(0, 0, int(schedule.FrequencyValue)*7)
		case "month":
			nextRun = from.AddDate(0, int(schedule.FrequencyValue), 0)
		default:
			log.Printf("Warning: Unrecognized frequency unit '%s', defaulting to 24h interval", schedule.FrequencyUnit)
			nextRun = from.Add(24 * time.Hour)
		}
	}

	log.Printf("Calculated next run time: %v", nextRun)
	return nextRun
}
