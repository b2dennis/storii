package constants

// Content Types
const (
	ContentTypeJSON = "application/json"
	ContentTypeText = "text/plain"
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
