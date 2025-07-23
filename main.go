package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

var config Config = Config{
	Address:   ":9999",
	DBPath:    "data.db",
	JWTSecret: "b2dennis",
	JWTExpiry: 24 * time.Hour,
}

func main() {
	fmt.Println("Reading .env file")
	godotenv.Load()

	fmt.Println("Loading config")
	loadConfig()

	fmt.Println("Initializing validator")
	initValidator()

	fmt.Println("Initializing JWT secret")

	fmt.Println("Initializing DB connection")
	var err error
	db, err = gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database")
	}

	fmt.Println("Running DB migrations")
	runDbMigrations()

	fmt.Println("Initializing router")
	r := mux.NewRouter()

	registerHandlers(r)

	fmt.Printf("Starting HTTP server at %s\n", config.Address)

	r.Use(rateLimitMiddleware)

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
}
