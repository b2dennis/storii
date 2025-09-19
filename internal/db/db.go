package db

import (
	"fmt"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DbManager struct {
	Db *gorm.DB
}

func NewDbManager(config *config.ServerConfig) *DbManager {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Europe/Zurich", config.DBHost, config.DBUser, config.DBPass, config.DBName, config.DBPort)
	Db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %s", dsn))
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
