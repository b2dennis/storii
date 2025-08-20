package constants

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
	MessagePasswordSet      = "password_set"
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

type ContextKey = string
