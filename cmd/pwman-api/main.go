package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

var config Config = Config{
	Address:   ":9999",
	DBPath:    "./data.db",
	JWTSecret: "b2dennis",
	JWTExpiry: 24 * time.Hour,
	LogOutput: os.Stdout,
}

func main() {


func loadConfig() {
	address := os.Getenv(VarAddress)
	dbPath := os.Getenv(VarDBPath)
	jwtSecret := os.Getenv(VarJWTSecret)
	jwtExpiry := os.Getenv(VarJWTExpiry)
	logOutput := os.Getenv(VarLogOutput)

	if address != "" {
		config.Address = address
	}

	if dbPath != "" {
		config.DBPath = dbPath
	}

	if jwtSecret != "" {
		config.JWTSecret = jwtSecret
	}

	if jwtExpiry != "" {
		hours, err := strconv.Atoi(jwtExpiry)
		if err == nil {
			config.JWTExpiry = time.Hour * time.Duration(hours)
		}
	}

	switch strings.ToLower(logOutput) {
	case "stdout":
		config.LogOutput = os.Stdout
	case "stderr":
		config.LogOutput = os.Stderr
	default:
		break
	}
}
