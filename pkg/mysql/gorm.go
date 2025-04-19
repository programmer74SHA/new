package mysql

import (
	"fmt"
	"log"

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
	err := db.AutoMigrate(
		&types.User{},
		&types.Asset{},
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
