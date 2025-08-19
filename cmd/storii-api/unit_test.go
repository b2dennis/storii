// AI Generated
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/b2dennis/storii/internal/auth"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/db"
	"github.com/b2dennis/storii/internal/handlers"
	"github.com/b2dennis/storii/internal/logging"
	"github.com/b2dennis/storii/internal/middleware"
	"github.com/b2dennis/storii/internal/models"
	"github.com/b2dennis/storii/internal/utils"
	"github.com/b2dennis/storii/internal/validation"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func setupTestConfig() *config.ServerConfig {
	testConfig := &config.ServerConfig{
		JWTSecret: "test-secret-key",
		JWTExpiry: time.Hour * 24,
		LogOutput: &bytes.Buffer{},
		DBPath:    ":memory:",
	}
	return testConfig
}

func setupValidator() *validation.Validator {
	return validation.NewValidator()
}

func setupJWTService(conf *config.ServerConfig) *auth.JWTService {
	return auth.NewJWTService(conf)
}

func createTestUser(t *testing.T, db *gorm.DB, username, password string) models.User {
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash test password: %v", err)
	}

	user := models.User{
		Username:     username,
		PasswordHash: passwordHash,
	}

	result := db.Create(&user)
	if result.Error != nil {
		t.Fatalf("Failed to create test user: %v", result.Error)
	}

	return user
}

func createTestPassword(t *testing.T, db *gorm.DB, userID uint, name string) models.StoredPassword {
	password := models.StoredPassword{
		UserID:        userID,
		Name:          name,
		Value:         make([]byte, 256),
		IV:            make([]byte, 12),
		AuthTag:       make([]byte, 16),
		Salt:          make([]byte, 16),
		AssociatedURL: "https://example.com",
	}

	for i := range password.Value {
		password.Value[i] = byte(i % 256)
	}
	for i := range password.IV {
		password.IV[i] = byte(i)
	}
	for i := range password.AuthTag {
		password.AuthTag[i] = byte(i)
	}
	for i := range password.Salt {
		password.Salt[i] = byte(i)
	}

	result := db.Create(&password)
	if result.Error != nil {
		t.Fatalf("Failed to create test password: %v", result.Error)
	}

	return password
}

// Auth tests
func TestGenerateJWT(t *testing.T) {
	conf := setupTestConfig()
	jwt := setupJWTService(conf)

	tests := []struct {
		name        string
		user        models.User
		expectError bool
	}{
		{
			name: "Valid user",
			user: models.User{
				Username: "testuser",
			},
			expectError: false,
		},
		{
			name: "User with ID",
			user: models.User{
				Username: "testuser",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.user.ID = 1
			token, err := jwt.GenerateJWT(tt.user)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && token == "" {
				t.Error("Expected token but got empty string")
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	conf := setupTestConfig()
	jwt := setupJWTService(conf)

	user := models.User{Username: "testuser"}
	user.ID = 1

	validToken, err := jwt.GenerateJWT(user)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		expectError bool
		expectedUID uint
	}{
		{
			name:        "Valid token",
			token:       validToken,
			expectError: false,
			expectedUID: 1,
		},
		{
			name:        "Invalid token",
			token:       "invalid.token.here",
			expectError: true,
		},
		{
			name:        "Empty token",
			token:       "",
			expectError: true,
		},
		{
			name:        "Malformed token",
			token:       "not.a.jwt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := jwt.ValidateJWT(tt.token)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && claims.UserID != tt.expectedUID {
				t.Errorf("Expected UserID %d, got %d", tt.expectedUID, claims.UserID)
			}
		})
	}
}

func TestValidateJWTExpired(t *testing.T) {
	conf := setupTestConfig()
	conf.JWTExpiry = -time.Hour

	jwt := setupJWTService(conf)

	user := models.User{Username: "testuser"}
	user.ID = 1

	expiredToken, err := jwt.GenerateJWT(user)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	_, err = jwt.ValidateJWT(expiredToken)
	if err == nil {
		t.Error("Expected error for expired token but got none")
	}
}

func TestExtractJWTFromHeader(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "Valid Bearer token",
			header:        "Bearer valid-token-here",
			expectError:   false,
			expectedToken: "valid-token-here",
		},
		{
			name:        "Missing Authorization header",
			header:      "",
			expectError: true,
		},
		{
			name:        "Invalid format - no Bearer",
			header:      "valid-token-here",
			expectError: true,
		},
		{
			name:        "Invalid format - wrong prefix",
			header:      "Basic valid-token-here",
			expectError: true,
		},
		{
			name:        "Invalid format - too many parts",
			header:      "Bearer token part extra",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			token, err := middleware.ExtractJWTFromHeader(req)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && token != tt.expectedToken {
				t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:        "Valid password",
			password:    "ValidPassword123!",
			expectError: false,
		},
		{
			name:        "Empty password",
			password:    "",
			expectError: false,
		},
		{
			name:        "Long password",
			password:    strings.Repeat("a", 100),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := auth.HashPassword(tt.password)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError && hash == "" {
				t.Error("Expected hash but got empty string")
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "TestPassword123!"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		expected bool
	}{
		{
			name:     "Correct password",
			password: password,
			hash:     string(hash),
			expected: true,
		},
		{
			name:     "Wrong password",
			password: "WrongPassword",
			hash:     string(hash),
			expected: false,
		},
		{
			name:     "Empty password",
			password: "",
			hash:     string(hash),
			expected: false,
		},
		{
			name:     "Invalid hash",
			password: password,
			hash:     "invalid-hash",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.CheckPasswordHash(tt.password, tt.hash)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Validation tests
func TestValidatePasswordStrength(t *testing.T) {
	val := setupValidator()

	tests := []struct {
		name     string
		password string
		expected bool
	}{
		{
			name:     "Strong password with all criteria",
			password: "StrongPass123!",
			expected: true,
		},
		{
			name:     "Password with 3 criteria (no special)",
			password: "StrongPass123",
			expected: true,
		},
		{
			name:     "Password with 3 criteria (no uppercase)",
			password: "strongpass123!",
			expected: true,
		},
		{
			name:     "Password with only 2 criteria",
			password: "strongpass",
			expected: false,
		},
		{
			name:     "Empty password",
			password: "",
			expected: false,
		},
		{
			name:     "Only numbers",
			password: "12345678",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := models.CreateUserC2S{
				Username: "testuser",
				Password: tt.password,
			}

			errors := val.ValidateStruct(request)
			hasPasswordError := len(errors) > 0

			if tt.expected && hasPasswordError {
				t.Errorf("Password %s should be valid but got validation error", tt.password)
			}
			if !tt.expected && !hasPasswordError {
				t.Errorf("Password %s should be invalid but passed validation", tt.password)
			}
		})
	}
}

func TestValidateUsernameFormat(t *testing.T) {
	val := setupValidator()

	tests := []struct {
		name     string
		username string
		expected bool
	}{
		{
			name:     "Valid username",
			username: "validuser123",
			expected: true,
		},
		{
			name:     "Username with underscores",
			username: "valid_user",
			expected: true,
		},
		{
			name:     "Username with dashes",
			username: "valid-user",
			expected: true,
		},
		{
			name:     "Username starting with number",
			username: "123invalid",
			expected: false,
		},
		{
			name:     "Username with special characters",
			username: "invalid@user",
			expected: false,
		},
		{
			name:     "Username starting with underscore",
			username: "_invalid",
			expected: false,
		},
		{
			name:     "Empty username",
			username: "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := models.CreateUserC2S{
				Username: tt.username,
				Password: "ValidPassword123!",
			}

			errors := val.ValidateStruct(request)
			hasUsernameFormatError := false
			for _, err := range errors {
				if strings.Contains(err, "username can only contain") {
					hasUsernameFormatError = true
					break
				}
			}

			if tt.expected && hasUsernameFormatError {
				t.Errorf("Username %s should be valid but got format error", tt.username)
			}
			if !tt.expected && !hasUsernameFormatError && tt.username != "" {
				t.Errorf("Username %s should be invalid but passed format validation", tt.username)
			}
		})
	}
}

// User handler tests
func TestCreateUser(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	uhm := handlers.NewUserHandlerManager(jwt, jwtService, logger, responseWriter, validator, dbm)

	tests := []struct {
		name           string
		requestBody    models.CreateUserC2S
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid user creation",
			requestBody: models.CreateUserC2S{
				Username: "testuser",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "Duplicate username",
			requestBody: models.CreateUserC2S{
				Username: "testuser",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusConflict,
			expectError:    true,
		},
		{
			name: "Invalid password",
			requestBody: models.CreateUserC2S{
				Username: "testuser2",
				Password: "weak",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Invalid username",
			requestBody: models.CreateUserC2S{
				Username: "123invalid",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/user/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			uhm.CreateUser(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectError {
				var errorResp models.ErrorS2C
				json.NewDecoder(w.Body).Decode(&errorResp)
				if errorResp.Error == "" {
					t.Error("Expected error response but got none")
				}
			} else {
				var successResp models.SuccessS2C
				json.NewDecoder(w.Body).Decode(&successResp)
				if successResp.Message != "ok" {
					t.Error("Expected success response")
				}
			}
		})
	}
}

func TestLoginUser(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	uhm := handlers.NewUserHandlerManager(jwt, jwtService, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")

	tests := []struct {
		name           string
		requestBody    models.LoginC2S
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid login",
			requestBody: models.LoginC2S{
				Username: "testuser",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Wrong password",
			requestBody: models.LoginC2S{
				Username: "testuser",
				Password: "WrongPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name: "Non-existent user",
			requestBody: models.LoginC2S{
				Username: "nonexistent",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/user/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			uhm.LoginUser(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectError {
				var errorResp models.ErrorS2C
				json.NewDecoder(w.Body).Decode(&errorResp)
				if errorResp.Error == "" {
					t.Error("Expected error response but got none")
				}
			} else {
				var successResp models.SuccessS2C
				var loginResp models.LoginS2C
				json.NewDecoder(w.Body).Decode(&successResp)

				dataBytes, _ := json.Marshal(successResp.Data)
				json.Unmarshal(dataBytes, &loginResp)

				if loginResp.Token == "" {
					t.Error("Expected token in response")
				}
				if loginResp.UserID != testUser.ID {
					t.Errorf("Expected UserID %d, got %d", testUser.ID, loginResp.UserID)
				}
			}
		})
	}
}

// Password handler tests
func TestGetPasswords(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	createTestPassword(t, dbm.Db, testUser.ID, "testpassword")

	token, err := jwtService.GenerateJWT(testUser)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwt.JwtMiddleware(phm.GetPasswords)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response models.SuccessS2C
	json.NewDecoder(w.Body).Decode(&response)

	var passwordsResp models.GetPasswordsS2C
	dataBytes, _ := json.Marshal(response.Data)
	json.Unmarshal(dataBytes, &passwordsResp)

	if len(passwordsResp.Passwords) != 1 {
		t.Errorf("Expected 1 password, got %d", len(passwordsResp.Passwords))
	}

	if passwordsResp.Passwords[0].Name != "testpassword" {
		t.Errorf("Expected password name 'testpassword', got '%s'", passwordsResp.Passwords[0].Name)
	}
}

func TestAddPassword(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	token, _ := jwtService.GenerateJWT(testUser)

	value := make([]byte, 256)
	iv := make([]byte, 12)
	authTag := make([]byte, 16)
	salt := make([]byte, 16)

	tests := []struct {
		name           string
		requestBody    models.AddPasswordC2S
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid password addition",
			requestBody: models.AddPasswordC2S{
				Name:          "newpassword",
				Value:         hex.EncodeToString(value),
				IV:            hex.EncodeToString(iv),
				AuthTag:       hex.EncodeToString(authTag),
				Salt:          hex.EncodeToString(salt),
				AssociatedURL: "https://example.com",
			},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "Duplicate password name",
			requestBody: models.AddPasswordC2S{
				Name:          "newpassword",
				Value:         hex.EncodeToString(value),
				IV:            hex.EncodeToString(iv),
				AuthTag:       hex.EncodeToString(authTag),
				Salt:          hex.EncodeToString(salt),
				AssociatedURL: "https://example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Invalid hex data",
			requestBody: models.AddPasswordC2S{
				Name:          "invalidhex",
				Value:         "invalid-hex-data",
				IV:            hex.EncodeToString(iv),
				AuthTag:       hex.EncodeToString(authTag),
				Salt:          hex.EncodeToString(salt),
				AssociatedURL: "https://example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/password/create", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			jwt.JwtMiddleware(phm.AddPassword)(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectError {
				var errorResp models.ErrorS2C
				json.NewDecoder(w.Body).Decode(&errorResp)
				if errorResp.Error == "" {
					t.Error("Expected error response but got none")
				}
			}
		})
	}
}

// Middleware tests
func TestJWTMiddleware(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)

	testUser := models.User{Username: "testuser"}
	testUser.ID = 1
	validToken, _ := jwtService.GenerateJWT(testUser)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectCall     bool
	}{
		{
			name:           "Valid token",
			authHeader:     "Bearer " + validToken,
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "Missing auth header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectCall:     false,
		},
		{
			name:           "Invalid token format",
			authHeader:     "InvalidToken",
			expectedStatus: http.StatusUnauthorized,
			expectCall:     false,
		},
		{
			name:           "Invalid token",
			authHeader:     "Bearer invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			expectCall:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := jwt.JwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if called != tt.expectCall {
				t.Errorf("Expected handler call %v, got %v", tt.expectCall, called)
			}
		})
	}
}

// Context middleware tests
func TestContextMiddleware(t *testing.T) {
	handler := middleware.ContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(constants.ContextKeyRequestId) == nil {
			t.Error("Request ID not set in context")
		}
		if r.Context().Value(constants.ContextKeyIPAddress) == nil {
			t.Error("IP address not set in context")
		}
		if r.Context().Value(constants.ContextKeyPath) == nil {
			t.Error("Path not set in context")
		}
		if r.Context().Value(constants.ContextKeyMethod) == nil {
			t.Error("Method not set in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// Utility function tests
func TestWriteErrorResponse(t *testing.T) {
	conf := setupTestConfig()
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)

	w := httptest.NewRecorder()
	ctx := context.Background()

	responseWriter.WriteErrorResponse(ctx, w, http.StatusBadRequest, constants.ErrorInvalidJson, "Test error message")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var response models.ErrorS2C
	json.NewDecoder(w.Body).Decode(&response)

	if response.Error != constants.ErrorInvalidJson {
		t.Errorf("Expected error code %s, got %s", constants.ErrorInvalidJson, response.Error)
	}

	if response.Message != "Test error message" {
		t.Errorf("Expected message 'Test error message', got '%s'", response.Message)
	}
}

func TestWriteSuccessResponse(t *testing.T) {
	conf := setupTestConfig()
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)

	w := httptest.NewRecorder()
	ctx := context.Background()
	testData := map[string]string{"test": "data"}

	responseWriter.WriteSuccessResponse(ctx, w, testData, http.StatusCreated)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var response models.SuccessS2C
	json.NewDecoder(w.Body).Decode(&response)

	if response.Message != constants.ResponseSuccess {
		t.Errorf("Expected message %s, got %s", constants.ResponseSuccess, response.Message)
	}
}

// Integration test
func TestUserPasswordFlow(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)
	uhm := handlers.NewUserHandlerManager(jwt, jwtService, logger, responseWriter, validator, dbm)

	// 1. Create user
	createUserReq := models.CreateUserC2S{
		Username: "integrationuser",
		Password: "IntegrationTest123!",
	}

	body, _ := json.Marshal(createUserReq)
	req := httptest.NewRequest("POST", "/user/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	uhm.CreateUser(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create user: status %d", w.Code)
	}

	// 2. Login user
	loginReq := models.LoginC2S{
		Username: "integrationuser",
		Password: "IntegrationTest123!",
	}

	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/user/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	uhm.LoginUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login user: status %d", w.Code)
	}

	var loginResponse models.SuccessS2C
	var loginData models.LoginS2C
	json.NewDecoder(w.Body).Decode(&loginResponse)
	dataBytes, _ := json.Marshal(loginResponse.Data)
	json.Unmarshal(dataBytes, &loginData)

	token := loginData.Token

	// 3. Add password
	value := make([]byte, 256)
	iv := make([]byte, 12)
	authTag := make([]byte, 16)
	salt := make([]byte, 16)

	addPasswordReq := models.AddPasswordC2S{
		Name:          "testsite",
		Value:         hex.EncodeToString(value),
		IV:            hex.EncodeToString(iv),
		AuthTag:       hex.EncodeToString(authTag),
		Salt:          hex.EncodeToString(salt),
		AssociatedURL: "https://testsite.com",
	}

	body, _ = json.Marshal(addPasswordReq)
	req = httptest.NewRequest("POST", "/password/create", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwt.JwtMiddleware(phm.AddPassword)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to add password: status %d", w.Code)
	}

	// 4. Get passwords
	req = httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwt.JwtMiddleware(phm.GetPasswords)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get passwords: status %d", w.Code)
	}

	var getPasswordsResponse models.SuccessS2C
	var passwordsData models.GetPasswordsS2C
	json.NewDecoder(w.Body).Decode(&getPasswordsResponse)
	dataBytes, _ = json.Marshal(getPasswordsResponse.Data)
	json.Unmarshal(dataBytes, &passwordsData)

	if len(passwordsData.Passwords) != 1 {
		t.Errorf("Expected 1 password, got %d", len(passwordsData.Passwords))
	}

	if passwordsData.Passwords[0].Name != "testsite" {
		t.Errorf("Expected password name 'testsite', got '%s'", passwordsData.Passwords[0].Name)
	}

	// 5. Update password
	updatePasswordReq := models.UpdatePasswordC2S{
		AddPasswordC2S: models.AddPasswordC2S{
			Name:          "testsite",
			Value:         hex.EncodeToString(value),
			IV:            hex.EncodeToString(iv),
			AuthTag:       hex.EncodeToString(authTag),
			Salt:          hex.EncodeToString(salt),
			AssociatedURL: "https://updated-testsite.com",
		},
		NewName: "updated-testsite",
	}

	body, _ = json.Marshal(updatePasswordReq)
	req = httptest.NewRequest("PUT", "/password/update", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwt.JwtMiddleware(phm.UpdatePassword)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to update password: status %d", w.Code)
	}

	// 6. Delete password
	deletePasswordReq := models.DeletePasswordC2S{
		Name: "updated-testsite",
	}

	body, _ = json.Marshal(deletePasswordReq)
	req = httptest.NewRequest("DELETE", "/password/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwt.JwtMiddleware(phm.DeletePassword)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to delete password: status %d", w.Code)
	}

	// 7. Verify password is deleted
	req = httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwt.JwtMiddleware(phm.GetPasswords)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get passwords after deletion: status %d", w.Code)
	}

	json.NewDecoder(w.Body).Decode(&getPasswordsResponse)
	dataBytes, _ = json.Marshal(getPasswordsResponse.Data)
	json.Unmarshal(dataBytes, &passwordsData)

	if len(passwordsData.Passwords) != 0 {
		t.Errorf("Expected 0 passwords after deletion, got %d", len(passwordsData.Passwords))
	}
}

// Additional edge case tests
func TestDeletePasswordNotFound(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	token, _ := jwtService.GenerateJWT(testUser)

	deletePasswordReq := models.DeletePasswordC2S{
		Name: "nonexistent",
	}

	body, _ := json.Marshal(deletePasswordReq)
	req := httptest.NewRequest("DELETE", "/password/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwt.JwtMiddleware(phm.DeletePassword)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdatePasswordNotFound(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	token, _ := jwtService.GenerateJWT(testUser)

	value := make([]byte, 256)
	iv := make([]byte, 12)
	authTag := make([]byte, 16)
	salt := make([]byte, 16)

	updatePasswordReq := models.UpdatePasswordC2S{
		AddPasswordC2S: models.AddPasswordC2S{
			Name:          "nonexistent",
			Value:         hex.EncodeToString(value),
			IV:            hex.EncodeToString(iv),
			AuthTag:       hex.EncodeToString(authTag),
			Salt:          hex.EncodeToString(salt),
			AssociatedURL: "https://example.com",
		},
		NewName: "newname",
	}

	body, _ := json.Marshal(updatePasswordReq)
	req := httptest.NewRequest("PUT", "/password/update", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwt.JwtMiddleware(phm.UpdatePassword)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeleteUserSuccess(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	uhm := handlers.NewUserHandlerManager(jwt, jwtService, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	token, _ := jwtService.GenerateJWT(testUser)

	req := httptest.NewRequest("DELETE", "/user/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwt.JwtMiddleware(uhm.DeleteUser)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user is deleted
	var user models.User
	result := dbm.Db.Where("id = ?", testUser.ID).First(&user)
	if result.RowsAffected != 0 {
		t.Error("User should be deleted but still exists")
	}
}

func TestUpdateUserSuccess(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	uhm := handlers.NewUserHandlerManager(jwt, jwtService, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	token, _ := jwtService.GenerateJWT(testUser)

	updateUserReq := models.UpdateUserC2S{
		Username: "updateduser",
		Password: "UpdatedPassword123!",
	}

	body, _ := json.Marshal(updateUserReq)
	req := httptest.NewRequest("PUT", "/user/update", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwt.JwtMiddleware(uhm.UpdateUser)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user is updated
	var user models.User
	dbm.Db.Where("id = ?", testUser.ID).First(&user)
	if user.Username != "updateduser" {
		t.Errorf("Expected username 'updateduser', got '%s'", user.Username)
	}

	// Verify password is updated
	if !auth.CheckPasswordHash("UpdatedPassword123!", user.PasswordHash) {
		t.Error("Password was not updated correctly")
	}
}

func TestInvalidJSONRequests(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)
	uhm := handlers.NewUserHandlerManager(jwt, jwtService, logger, responseWriter, validator, dbm)

	testUser := createTestUser(t, dbm.Db, "testuser", "ValidPassword123!")
	token, _ := jwtService.GenerateJWT(testUser)

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		path    string
		body    string
		useAuth bool
	}{
		{
			name:    "Create user with invalid JSON",
			handler: uhm.CreateUser,
			method:  "POST",
			path:    "/user/register",
			body:    `{"invalid": json}`,
			useAuth: false,
		},
		{
			name:    "Login with invalid JSON",
			handler: uhm.LoginUser,
			method:  "POST",
			path:    "/user/login",
			body:    `{"invalid": json}`,
			useAuth: false,
		},
		{
			name:    "Add password with invalid JSON",
			handler: jwt.JwtMiddleware(phm.AddPassword),
			method:  "POST",
			path:    "/password/create",
			body:    `{"invalid": json}`,
			useAuth: true,
		},
		{
			name:    "Update user with invalid JSON",
			handler: jwt.JwtMiddleware(uhm.UpdateUser),
			method:  "PUT",
			path:    "/user/update",
			body:    `{"invalid": json}`,
			useAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.useAuth {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			w := httptest.NewRecorder()

			tt.handler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
			}

			var errorResp models.ErrorS2C
			json.NewDecoder(w.Body).Decode(&errorResp)
			if errorResp.Error != constants.ErrorInvalidJson {
				t.Errorf("Expected error code %s, got %s", constants.ErrorInvalidJson, errorResp.Error)
			}
		})
	}
}

func TestPasswordIsolationBetweenUsers(t *testing.T) {
	conf := setupTestConfig()
	jwtService := setupJWTService(conf)
	logger := logging.NewLogger(conf)
	responseWriter := utils.NewResponseWriter(logger)
	jwt := middleware.NewJWT(jwtService, responseWriter)
	validator := setupValidator()
	dbm := db.NewDbManager(conf)
	phm := handlers.NewPasswordHandlerManager(jwt, logger, responseWriter, validator, dbm)

	// Create two users
	user1 := createTestUser(t, dbm.Db, "user1", "ValidPassword123!")
	user2 := createTestUser(t, dbm.Db, "user2", "ValidPassword123!")

	// Create passwords for both users
	createTestPassword(t, dbm.Db, user1.ID, "user1password")
	createTestPassword(t, dbm.Db, user2.ID, "user2password")

	// Get passwords for user1
	token1, _ := jwtService.GenerateJWT(user1)
	req := httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()

	jwt.JwtMiddleware(phm.GetPasswords)(w, req)

	var response models.SuccessS2C
	var passwordsData models.GetPasswordsS2C
	json.NewDecoder(w.Body).Decode(&response)
	dataBytes, _ := json.Marshal(response.Data)
	json.Unmarshal(dataBytes, &passwordsData)

	// User1 should only see their own password
	if len(passwordsData.Passwords) != 1 {
		t.Errorf("User1 should see 1 password, got %d", len(passwordsData.Passwords))
	}
	if passwordsData.Passwords[0].Name != "user1password" {
		t.Errorf("User1 should see 'user1password', got '%s'", passwordsData.Passwords[0].Name)
	}

	// Get passwords for user2
	token2, _ := jwtService.GenerateJWT(user2)
	req = httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w = httptest.NewRecorder()

	jwt.JwtMiddleware(phm.GetPasswords)(w, req)

	json.NewDecoder(w.Body).Decode(&response)
	dataBytes, _ = json.Marshal(response.Data)
	json.Unmarshal(dataBytes, &passwordsData)

	// User2 should only see their own password
	if len(passwordsData.Passwords) != 1 {
		t.Errorf("User2 should see 1 password, got %d", len(passwordsData.Passwords))
	}
	if passwordsData.Passwords[0].Name != "user2password" {
		t.Errorf("User2 should see 'user2password', got '%s'", passwordsData.Passwords[0].Name)
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = auth.HashPassword(password)
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, _ := auth.HashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.CheckPasswordHash(password, hash)
	}
}

func BenchmarkGenerateJWT(b *testing.B) {
	conf := setupTestConfig()
	jwtService := auth.NewJWTService(conf)

	user := models.User{Username: "benchuser"}
	user.ID = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwtService.GenerateJWT(user)
	}
}

func BenchmarkValidateJWT(b *testing.B) {
	conf := setupTestConfig()
	jwtService := auth.NewJWTService(conf)

	user := models.User{Username: "benchuser"}
	user.ID = 1
	token, _ := jwtService.GenerateJWT(user)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwtService.ValidateJWT(token)
	}
}
