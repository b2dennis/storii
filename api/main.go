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
	DBPath:    "data.db",
	JWTSecret: "b2dennis",
	JWTExpiry: 24 * time.Hour,
	LogOutput: os.Stdout,
}

func main() {
	loadConfig()
	godotenv.Load()
	initLogger()

	contextLogger.Info("Initializing validator")
	initValidator()

	contextLogger.Info("Initializing JWT secret")

	contextLogger.Info("Initializing DB connection")
	var err error
	db, err = gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic("failed to connect to database")
	}

	contextLogger.Info("Running DB migrations")
	runDbMigrations()

	contextLogger.Info("Initializing router")
	r := mux.NewRouter()

	registerHandlers(r)

	contextLogger.Info(fmt.Sprintf("Starting HTTP server at %s\n", config.Address))

	r.Use(contextMiddleware, loggingMiddleware, rateLimitMiddleware)

	http.ListenAndServe(config.Address, handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"GET", "POST", "PUT", "DELETE"}),
		handlers.AllowedHeaders([]string{"Authorization"}),
		handlers.AllowedOrigins([]string{"*"}),
	)(r))
}

func registerHandlers(r *mux.Router) {
	registerPasswordHandlers(r)
	registerUserHandlers(r)
}

func runDbMigrations() {
	db.AutoMigrate(&StoredPassword{})
	db.AutoMigrate(&User{})
}

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
