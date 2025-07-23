// Constant definitions

package main

// Env Var Names
const (
	VarAddress   = "ADDRESS"
	VarDBPath    = "DBPATH"
	VarJWTSecret = "JWTSECRET"
	VarJWTExpiry = "JWTEXPIRY"
)

// Content Types
const (
	ContentTypeJSON = "application/json"
	ContentTypeText = "text/plain"
)

// Success Response
const ResponseSuccess = "ok"

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
	ErrorRateLimit          = "rate_limit"
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
	UserRouteDelete   = "/delete"
	UserRouteUpdate   = "/update"
)

// Password Routes
const (
	PasswordRouteFetch  = ""
	PasswordRouteAdd    = "/create"
	PasswordRouteDelete = "/delete"
	PasswordRouteUpdate = "/update"
)

// Middleware Headers
const (
	AuthHeaderUserID   = "X-User-ID"
	AuthHeaderUsername = "X-Username"
)
