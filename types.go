package main

import (
	"net/http"

	"gorm.io/gorm"
)

// General
type Config struct {
	Address string
}

// Request Handlers
type RequestHandlerStruct struct {
	Handler func(http.ResponseWriter, *http.Request)
	Method  string
	Route   string
}

// DB
type StoredPassword struct {
	gorm.Model
	UserID        uint   `gorm:"not null"`
	Name          string `gorm:"not null"`
	Value         string `gorm:"not null"`
	IV            string `gorm:"not null"`
	AssociatedURL string
}

type User struct {
	gorm.Model
	Username        string           `gorm:"uniqueIndex;not null"`
	PasswordHash    string           `gorm:"not null"`
	StoredPasswords []StoredPassword `gorm:"foreignKey:UserID"`
}

// API Requests JSON
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
