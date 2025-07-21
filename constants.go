// Constant definitions

package main

// Content Types
const (
	ContentTypeJSON = "application/json"
	ContentTypeText = "text/plain"
)

// Error Codes
const (
	ErrorInvalidJson    = "invalid_json"
	ErrorInvalidInput   = "invalid_input"
	ErrorCreationFailed = "creation_failed"
	ErrorUserExists     = "user_already_exists"
	ErrorValidation     = "validation_error"
	ErrorInternalServer = "internal_server_error"
	ErrorUnauthorized   = "unauthorized"
	ErrorForbidden      = "forbidden"
	ErrorNotFound       = "not_found"
)

// API Subroutes
const (
	SubrouteUser     = "/user"
	SubroutePassword = "/password"
)
