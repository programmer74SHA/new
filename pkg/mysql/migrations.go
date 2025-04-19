package mysql

import (
	"log"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/gorm"
)

func AddMigrations(db *gorm.DB) error {
	// Add the AssetIP migration
	if err := MigrateAssetIPsTable(db); err != nil {
		log.Printf("Error migrating asset IPs table: %v", err)
		return err
	}

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

// MigrateAssetIPsTable migrates IP data from the assets table to the asset_ips table
func MigrateAssetIPsTable(db *gorm.DB) error {
	// Check if asset_ips table exists
	var tableExists bool
	err := db.Raw("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_name = 'asset_ips'").Scan(&tableExists).Error
	if err != nil {
		return err
	}

	if !tableExists {
		// Create asset_ips table
		err = db.AutoMigrate(&types.AssetIP{})
		if err != nil {
			return err
		}

		// Check if ip_address column exists in assets table
		var ipColumnExists bool
		err = db.Raw("SELECT COUNT(*) > 0 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'assets' AND COLUMN_NAME = 'ip_address'").Scan(&ipColumnExists).Error
		if err != nil {
			return err
		}

		if ipColumnExists {
			// Migrate existing data - copy IPs from assets to asset_ips
			rows, err := db.Raw("SELECT id, ip_address, created_at, updated_at FROM assets WHERE deleted_at IS NULL AND ip_address IS NOT NULL AND ip_address != ''").Rows()
			if err != nil {
				return err
			}
			defer rows.Close()

			tx := db.Begin()
			if tx.Error != nil {
				return tx.Error
			}

			// Process each asset
			for rows.Next() {
				var (
					id        string
					ipAddress string
					createdAt time.Time
					updatedAt *time.Time
				)

				if err := rows.Scan(&id, &ipAddress, &createdAt, &updatedAt); err != nil {
					tx.Rollback()
					return err
				}

				// Create AssetIP entry
				assetIP := types.AssetIP{
					ID:        uuid.New().String(),
					AssetID:   id,
					IPAddress: ipAddress,
					CreatedAt: createdAt,
					UpdatedAt: updatedAt,
				}

				if err := tx.Table("asset_ips").Create(&assetIP).Error; err != nil {
					tx.Rollback()
					return err
				}
			}

			// Commit the transaction for creating asset IPs
			if err := tx.Commit().Error; err != nil {
				return err
			}

			// Start a new transaction to drop the column
			tx = db.Begin()
			if tx.Error != nil {
				return tx.Error
			}

			// Remove ip_address column from assets table
			if err := tx.Exec("ALTER TABLE assets DROP COLUMN ip_address").Error; err != nil {
				tx.Rollback()
				return err
			}

			// Commit the transaction for dropping the column
			if err := tx.Commit().Error; err != nil {
				return err
			}

			log.Println("Successfully migrated IP addresses from assets table to asset_ips table")
		}
	}

	return nil
}
