// Constant definitions

package main

// Content Types
const (
	ContentTypeJSON = "application/json"
	ContentTypeText = "text/plain"
)

// Error Codes
const (
	ErrorInvalidID          = "invalid_id"
	ErrorInvalidCredentials = "invalid_credentials"
	ErrorUserPassMissing    = "user_or_pass_missing"
	ErrorInvalidJson        = "invalid_json"
	ErrorInvalidInput       = "invalid_input"
	ErrorCreationFailed     = "creation_failed"
	ErrorDuplicatePassword  = "duplicate_password_name"
	ErrorUserExists         = "user_already_exists"
	ErrorValidation         = "validation_error"
	ErrorInternalServer     = "internal_server_error"
	ErrorUnauthorized       = "unauthorized"
	ErrorForbidden          = "forbidden"
	ErrorNotFound           = "not_found"
)

// Auth Error Codes
const (
	AuthErrorInvalidToken  = "invalid_token"
	AuthErrorHeaderMissing = "auth_header_missing"
	AuthErrorHeaderInvalid = "auth_header_invalid"
)

// API Subroutes
const (
	SubrouteUser     = "/user"
	SubroutePassword = "/password"
)

// User Routes
const (
	UserRouteRegister = "/register"
	UserRouteLogin    = "/login"
)

// Middleware Headers
const (
	AuthHeaderUserID   = "X-User-ID"
	AuthHeaderUsername = "X-Username"
)
