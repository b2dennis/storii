package db

import (
	"fmt"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DbManager struct {
	Db *gorm.DB
}

func NewDbManager(config *config.ServerConfig) *DbManager {
	Db, err := gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %s", config.DBPath))
	}

	err = Db.AutoMigrate(&models.User{}, &models.StoredPassword{})
	if err != nil {
		panic(fmt.Sprintf("Failed to migrate test database: %v", err))
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
