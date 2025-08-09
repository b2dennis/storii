package db

import (
	"b2dennis/pwman-api/internal/config"
	"b2dennis/pwman-api/internal/models"
	"fmt"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DbManager struct {
	Db *gorm.DB
}

func NewDbManager(config *config.Config) *DbManager {
	Db, err := gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})

	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %s", config.DBPath))
	}

	dbmanager := &DbManager{
		Db: Db,
	}

	dbmanager.runDbMigrations()

	return dbmanager
}

func (dbm *DbManager) runDbMigrations() {
	dbm.Db.AutoMigrate(&models.StoredPassword{})
	dbm.Db.AutoMigrate(&models.User{})
}
