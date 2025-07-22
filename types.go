// Struct definitions

package main

import (
	"net/http"
	"time"

	"gorm.io/gorm"
)

// General
type Config struct {
	Address   string
	DBPath    string
	JWTSecret string
	JWTExpiry time.Duration
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

// API JSON Structs
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// Password max len of 72 because of bcrypt limitations
type CreateUserRequest struct {
	Username string `json:"username" validate:"min=4,max=32"`
	Password string `json:"password" validate:"min=12,max=72"`
}

type CreateUserSuccess struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"min=4,max=32"`
	Password string `json:"password" validate:"min=12,max=72"`
}

type LoginSuccess struct {
	Token    string `json:"token"`
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
}

type ResponsePassword struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	IV            string `json:"iv"`
	AssociatedURL string `json:"associated_url,omitempty"`
}

type GetPasswordsSuccess struct {
	Passwords []ResponsePassword `json:"passwords"`
}

type AddPasswordRequest struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	IV            string `json:"iv"`
	AssociatedURL string `json:"associated_url"`
}

type AddPasswordSuccess struct {
	NewPassword ResponsePassword `json:"new_password"`
}

type DeletePasswordRequest struct {
	Name string `json:"name" validate:"max=32,min=12"`
}
