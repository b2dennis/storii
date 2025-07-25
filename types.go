// Struct definitions

package main

import (
	"context"
	"net/http"
	"time"

	"log/slog"

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
	Value         []byte `gorm:"type:VARBINARY(256);not null"`
	IV            []byte `gorm:"type:BINARY(12);not null"`
	AuthTag       []byte `gorm:"type:BINARY(16);not null"`
	Salt          []byte `gorm:"type:BINARY(16);not null"`
	AssociatedURL string
}

type User struct {
	gorm.Model      `validate:"-"`
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
	Message string `json:"message,omitempty"`
	Data    any    `json:"data"`
}

// Password max len of 72 because of bcrypt limitations
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=4,max=32,username_format"`
	Password string `json:"password" validate:"required,min=12,max=72,password_strength"`
}

type CreateUserSuccess struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required,min=4,max=32,username_format"`
	Password string `json:"password" validate:"required,min=12,max=72,password_strength"`
}

type LoginSuccess struct {
	Token    string `json:"token"`
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
}

type DeleteUserSuccess struct {
	UserID uint `json:"user_id"`
}

type UpdateUserRequest = CreateUserRequest
type UpdateUserSuccess = CreateUserSuccess

type ResponsePassword struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	IV            string `json:"iv"`
	AuthTag       string `json:"auth_tag"`
	Salt          string `json:"salt"`
	AssociatedURL string `json:"associated_url,omitempty"`
}

type GetPasswordsSuccess struct {
	Passwords []ResponsePassword `json:"passwords"`
}

type AddPasswordRequest struct {
	Name          string `json:"name" validate:"required,min=1,max=100,password_name"`
	Value         string `json:"value" validate:"required,hexadecimal,len=512"`
	IV            string `json:"iv" validate:"required,hexadecimal,len=24"`
	AuthTag       string `json:"auth_tag" validate:"required,hexadecimal,len=32"`
	Salt          string `json:"salt" validate:"required,hexadecimal,len=32"`
	AssociatedURL string `json:"associated_url" validate:"omitempty,url,max=2048"`
}

type AddPasswordSuccess struct {
	NewPassword ResponsePassword `json:"new_password"`
}

type DeletePasswordRequest struct {
	Name string `json:"name" validate:"required,min=1,max=100,password_name"`
}

type DeletePasswordSuccess struct {
	Name string `json:"name"`
}

type UpdatePasswordRequest struct {
	AddPasswordRequest
	NewName string `json:"new_name" validate:"required,min=1,max=100,password_name"`
}

type UpdatePasswordSuccess = AddPasswordSuccess

// Context Key
type ContextKey = string

// Logger

type ContextHandler struct {
	handler slog.Handler
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, record slog.Record) error {
	if requestId := ctx.Value(ContextKeyRequestId); requestId != nil {
		record.AddAttrs(slog.Any(ContextKeyRequestId, requestId))
	}
	if ipAddress := ctx.Value(ContextKeyIPAddress); ipAddress != nil {
		record.AddAttrs(slog.String(ContextKeyIPAddress, ipAddress.(string)))
	}
	if path := ctx.Value(ContextKeyPath); path != nil {
		record.AddAttrs(slog.String(ContextKeyPath, path.(string)))
	}
	if method := ctx.Value(ContextKeyMethod); method != nil {
		record.AddAttrs(slog.String(ContextKeyMethod, method.(string)))
	}
	if userId := ctx.Value(ContextKeyUserID); userId != nil {
		record.AddAttrs(slog.Uint64(ContextKeyUserID, userId.(uint64)))
	}
	if username := ctx.Value(ContextKeyUsername); username != nil {
		record.AddAttrs(slog.String(ContextKeyUsername, username.(string)))
	}

	return h.handler.Handle(ctx, record)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{handler: h.handler.WithGroup(name)}
}
