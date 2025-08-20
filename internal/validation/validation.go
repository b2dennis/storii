package validation

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	validate *validator.Validate
}

func NewValidator() *Validator {
	validate := validator.New()

	validate.RegisterValidation("password_strength", validatePasswordStrength)
	validate.RegisterValidation("username_format", validateUsernameFormat)
	validate.RegisterValidation("password_name", validatePasswordName)

	return &Validator{
		validate,
	}
}

func validatePasswordStrength(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune(specialChars, char):
			hasSpecial = true
		}
	}

	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSpecial {
		count++
	}

	return count >= 3
}

func validateUsernameFormat(fl validator.FieldLevel) bool {
	username := fl.Field().String()

	for _, char := range username {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return false
		}
	}

	if len(username) > 0 {
		first := rune(username[0])
		return (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')
	}

	return true
}

func validatePasswordName(fl validator.FieldLevel) bool {
	name := fl.Field().String()

	trimmed := strings.TrimSpace(name)
	if len(trimmed) == 0 {
		return false
	}

	for _, char := range name {
		if char < 32 || char == 127 {
			return false
		}
	}

	return true
}

func (v *Validator) ValidateStruct(s any) []string {
	var errors []string

	err := v.validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, formatValidationError(err))
		}
	}

	return errors
}

func formatValidationError(err validator.FieldError) string {
	field := strings.ToLower(err.Field())
	tag := err.Tag()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", field, err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", field, err.Param())
	case "password_strength":
		return "password must contain at least 3 of: uppercase, lowercase, numbers, special characters"
	case "username_format":
		return "username can only contain letters, numbers, underscores, and dashes, and must start with a letter"
	case "password_name":
		return "password name cannot be empty or contain only whitespace"
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}
