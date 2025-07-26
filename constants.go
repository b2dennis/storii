// Constant definitions

package main

// Env Var Names
const (
	VarAddress   = "ADDRESS"
	VarDBPath    = "DBPATH"
	VarJWTSecret = "JWTSECRET"
	VarJWTExpiry = "JWTEXPIRY"
	VarLogOutput = "LOGOUTPUT"
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
	ErrorInvalidToken       = "invalid_token"
	ErrorAuthHeaderMissing  = "auth_header_missing"
	ErrorAuthHeaderInvalid  = "auth_header_invalid"
)

// API Subroutes
const (
	RouteUser     = "/user"
	RoutePassword = "/password"
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

// Logging Messages
const (
	MessageNewRequest       = "new_request"
	MessageRateLimited      = "rate_limit"
	MessageRouteRegistered  = "route_registered"
	MessageUserCreated      = "user_created"
	MessageUserLogin        = "user_login"
	MessageUserDeleted      = "user_deleted"
	MessageUserUpdated      = "user_updated"
	MessagePasswordsFetched = "passwords_fetched"
	MessagePasswordCreated  = "password_created"
	MessagePasswordDeleted  = "password_deleted"
	MessagePasswordUpdated  = "password_updated"
)

// Logging Keys
const (
	LogKeyRoute        = "route"
	LogKeySubroute     = "subroute"
	LogKeyMethod       = "method"
	LogKeyNewUsername  = "new_username"
	LogKeyPasswordName = "password_name"
)

// Context Keys
const (
	ContextKeyRequestId ContextKey = "request_id"
	ContextKeyIPAddress ContextKey = "ip_address"
	ContextKeyPath      ContextKey = "route"
	ContextKeyMethod    ContextKey = "method"
	ContextKeyUsername  ContextKey = "username"
	ContextKeyUserID    ContextKey = "user_id"
)
