package constants

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
