package mysql

import "gorm.io/gorm"

func AddMigrations(db *gorm.DB) error {
	// Add the next_run_time column to the schedules table if it doesn't exist
	var columnExists bool
	err := db.Raw("SELECT COUNT(*) > 0 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'schedules' AND COLUMN_NAME = 'next_run_time'").Scan(&columnExists).Error
	if err != nil {
		return err
	}

	if !columnExists {
		// Add the next_run_time column
		if err := db.Exec("ALTER TABLE schedules ADD COLUMN next_run_time DATETIME NULL AFTER minute").Error; err != nil {
			return err
		}

		// Set initial next_run_time for all existing schedules based on their frequency settings
		if err := db.Exec(`
			UPDATE schedules 
			SET next_run_time = 
				CASE 
					WHEN hour >= 0 AND minute >= 0 THEN
						CASE
							WHEN TIME(NOW()) > MAKETIME(hour, minute, 0) THEN
								CASE 
									WHEN frequency_unit = 'day' THEN DATE_ADD(DATE_ADD(DATE(NOW()), INTERVAL 1 DAY), INTERVAL MAKETIME(hour, minute, 0) HOUR_SECOND)
									WHEN frequency_unit = 'week' THEN DATE_ADD(DATE_ADD(DATE(NOW()), INTERVAL frequency_value * 7 DAY), INTERVAL MAKETIME(hour, minute, 0) HOUR_SECOND)
									WHEN frequency_unit = 'month' THEN DATE_ADD(DATE_ADD(DATE(NOW()), INTERVAL frequency_value MONTH), INTERVAL MAKETIME(hour, minute, 0) HOUR_SECOND)
									ELSE DATE_ADD(DATE(NOW()), INTERVAL MAKETIME(hour, minute, 0) HOUR_SECOND)
								END
							ELSE DATE_ADD(DATE(NOW()), INTERVAL MAKETIME(hour, minute, 0) HOUR_SECOND)
						END
					ELSE NULL
				END
			WHERE hour >= 0 AND minute >= 0 AND next_run_time IS NULL
		`).Error; err != nil {
			return err
		}

		// Then update the remaining schedules based on their frequency units
		if err := db.Exec("UPDATE schedules SET next_run_time = DATE_ADD(NOW(), INTERVAL frequency_value MINUTE) WHERE frequency_unit = 'minute' AND next_run_time IS NULL").Error; err != nil {
			return err
		}

		if err := db.Exec("UPDATE schedules SET next_run_time = DATE_ADD(NOW(), INTERVAL frequency_value HOUR) WHERE frequency_unit = 'hour' AND next_run_time IS NULL").Error; err != nil {
			return err
		}

		if err := db.Exec("UPDATE schedules SET next_run_time = DATE_ADD(NOW(), INTERVAL frequency_value DAY) WHERE frequency_unit = 'day' AND next_run_time IS NULL").Error; err != nil {
			return err
		}

		if err := db.Exec("UPDATE schedules SET next_run_time = DATE_ADD(NOW(), INTERVAL frequency_value * 7 DAY) WHERE frequency_unit = 'week' AND next_run_time IS NULL").Error; err != nil {
			return err
		}

		if err := db.Exec("UPDATE schedules SET next_run_time = DATE_ADD(NOW(), INTERVAL frequency_value MONTH) WHERE frequency_unit = 'month' AND next_run_time IS NULL").Error; err != nil {
			return err
		}

		// Make sure all schedules have a next_run_time
		if err := db.Exec("UPDATE schedules SET next_run_time = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE next_run_time IS NULL").Error; err != nil {
			return err
		}
	}

	// Check if 'Cancelled' is in the enum for scan_jobs status column
	var hasStatusCancelled bool
	err = db.Raw(`
		SELECT COUNT(*) > 0 
		FROM INFORMATION_SCHEMA.COLUMNS 
		WHERE TABLE_NAME = 'scan_jobs' 
		AND COLUMN_NAME = 'status' 
		AND COLUMN_TYPE LIKE '%Cancelled%'
	`).Scan(&hasStatusCancelled).Error
	if err != nil {
		return err
	}

	// Add 'Cancelled' to the status enum if it doesn't exist
	if !hasStatusCancelled {
		if err := db.Exec("ALTER TABLE scan_jobs MODIFY COLUMN status ENUM('Pending', 'Running', 'Completed', 'Failed', 'Error', 'Cancelled') NOT NULL DEFAULT 'Pending'").Error; err != nil {
			return err
		}
	}

	return nil
}
