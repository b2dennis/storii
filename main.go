package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

var config Config = Config{
	Address: ":9999",
}

func main() {
	fmt.Println("Initializing DB connection")
	var err error
	db, err = gorm.Open(sqlite.Open("data.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database")
	}

	fmt.Println("Running DB migrations")
	runDbMigrations()

	fmt.Println("Initializing router")
	r := mux.NewRouter()

	registerHandlers(r)

	fmt.Printf("Starting HTTP server at %s\n", config.Address)

	http.ListenAndServe(config.Address, r)
}

func registerHandlers(r *mux.Router) {
	registerPasswordHandlers(r)
	registerUserHandlers(r)
}

func runDbMigrations() {
	db.AutoMigrate(&StoredPassword{})
	db.AutoMigrate(&User{})
}
