package mysql

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/adapter/storage/types"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DBConnOptions struct {
	Host     string
	Port     uint
	Username string
	Password string
	Database string
}

func NewMysqlConnection(cfg DBConnOptions) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
	)
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
	})
}

func GormMigrations(db *gorm.DB) {
	// First create the tables
	err := db.AutoMigrate(
		&types.User{},
		&types.Asset{},
		&types.AssetIP{},
		&types.Scanner{},
		&types.ScanJob{},
		&types.Port{},
		&types.VMwareVM{},
		&types.AssetScanJob{},
		&types.NmapMetadata{},
		&types.NmapIPScan{},
		&types.NmapNetworkScan{},
		&types.NmapRangeScan{},
		&types.DomainMetadata{},
		&types.VcenterMetadata{},
		&types.Schedule{},
		&types.Session{},
	)
	if err != nil {
		log.Fatalf("failed to migrate models: %v", err)
	}
}

func SeedData(db *gorm.DB, hashPassword func(string) (string, error)) {
	var count int64
	db.Model(&types.User{}).Count(&count)
	if count == 0 { // Only insert if the table is empty
		hpassword, err := hashPassword("P@ssw0rd")
		if err != nil {
			log.Printf("Failed to hash password in seed data: %v", err)
			return
		}

		// Create empty strings for nullable fields
		emptyFirstName := ""
		emptyLastName := ""
		emptyEmail := ""

		user := types.User{
			ID:        uuid.New().String(),
			FirstName: &emptyFirstName,
			LastName:  &emptyLastName,
			Username:  "admin",
			Password:  hpassword,
			Email:     &emptyEmail,
			Role:      "admin",
			CreatedAt: time.Now(),
			// Let GORM handle UpdatedAt and DeletedAt with zero values
			Sessions: []types.Session{},
		}

		result := db.Create(&user)
		if result.Error != nil {
			log.Printf("Failed to seed database: %v", result.Error)
			return
		}
		fmt.Println("Seed data inserted successfully.")
	} else {
		fmt.Println("Database already seeded, skipping.")
	}
}
