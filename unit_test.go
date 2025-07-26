package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Test setup helpers
func setupTestDB(t *testing.T) *gorm.DB {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	err = testDB.AutoMigrate(&User{}, &StoredPassword{})
	if err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	return testDB
}

func setupTestConfig() {
	config.JWTSecret = "test-secret-key"
	config.JWTExpiry = time.Hour * 24
	config.LogOutput = &bytes.Buffer{}
	initLogger()
	initValidator()
}

func createTestUser(t *testing.T, db *gorm.DB, username, password string) User {
	passwordHash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash test password: %v", err)
	}

	user := User{
		Username:     username,
		PasswordHash: passwordHash,
	}

	result := db.Create(&user)
	if result.Error != nil {
		t.Fatalf("Failed to create test user: %v", result.Error)
	}

	return user
}

func createTestPassword(t *testing.T, db *gorm.DB, userID uint, name string) StoredPassword {
	password := StoredPassword{
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
	setupTestConfig()

	tests := []struct {
		name        string
		user        User
		expectError bool
	}{
		{
			name: "Valid user",
			user: User{
				Username: "testuser",
			},
			expectError: false,
		},
		{
			name: "User with ID",
			user: User{
				Username: "testuser",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.user.ID = 1
			token, err := generateJWT(tt.user)

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
	setupTestConfig()

	user := User{Username: "testuser"}
	user.ID = 1

	validToken, err := generateJWT(user)
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
			claims, err := validateJWT(tt.token)

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
	setupTestConfig()

	config.JWTExpiry = -time.Hour

	user := User{Username: "testuser"}
	user.ID = 1

	expiredToken, err := generateJWT(user)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	_, err = validateJWT(expiredToken)
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

			token, err := extractJWTFromHeader(req)

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
			hash, err := hashPassword(tt.password)

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
			result := checkPasswordHash(tt.password, tt.hash)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Validation tests
func TestValidatePasswordStrength(t *testing.T) {
	setupTestConfig()

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
			request := CreateUserRequest{
				Username: "testuser",
				Password: tt.password,
			}

			errors := validateStruct(request)
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
	setupTestConfig()

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
			request := CreateUserRequest{
				Username: tt.username,
				Password: "ValidPassword123!",
			}

			errors := validateStruct(request)
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
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	tests := []struct {
		name           string
		requestBody    CreateUserRequest
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid user creation",
			requestBody: CreateUserRequest{
				Username: "testuser",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name: "Duplicate username",
			requestBody: CreateUserRequest{
				Username: "testuser",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusConflict,
			expectError:    true,
		},
		{
			name: "Invalid password",
			requestBody: CreateUserRequest{
				Username: "testuser2",
				Password: "weak",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Invalid username",
			requestBody: CreateUserRequest{
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

			createUser(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectError {
				var errorResp ErrorResponse
				json.NewDecoder(w.Body).Decode(&errorResp)
				if errorResp.Error == "" {
					t.Error("Expected error response but got none")
				}
			} else {
				var successResp SuccessResponse
				json.NewDecoder(w.Body).Decode(&successResp)
				if successResp.Message != "ok" {
					t.Error("Expected success response")
				}
			}
		})
	}
}

func TestLoginUser(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")

	tests := []struct {
		name           string
		requestBody    LoginRequest
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid login",
			requestBody: LoginRequest{
				Username: "testuser",
				Password: "ValidPassword123!",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Wrong password",
			requestBody: LoginRequest{
				Username: "testuser",
				Password: "WrongPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name: "Non-existent user",
			requestBody: LoginRequest{
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

			loginUser(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectError {
				var errorResp ErrorResponse
				json.NewDecoder(w.Body).Decode(&errorResp)
				if errorResp.Error == "" {
					t.Error("Expected error response but got none")
				}
			} else {
				var successResp SuccessResponse
				var loginResp LoginSuccess
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
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	createTestPassword(t, testDB, testUser.ID, "testpassword")

	token, err := generateJWT(testUser)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	req := httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwtMiddleware(getPasswords)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response SuccessResponse
	json.NewDecoder(w.Body).Decode(&response)

	var passwordsResp GetPasswordsSuccess
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
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	token, _ := generateJWT(testUser)

	value := make([]byte, 256)
	iv := make([]byte, 12)
	authTag := make([]byte, 16)
	salt := make([]byte, 16)

	tests := []struct {
		name           string
		requestBody    AddPasswordRequest
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid password addition",
			requestBody: AddPasswordRequest{
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
			requestBody: AddPasswordRequest{
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
			requestBody: AddPasswordRequest{
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

			jwtMiddleware(addPassword)(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectError {
				var errorResp ErrorResponse
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
	setupTestConfig()

	testUser := User{Username: "testuser"}
	testUser.ID = 1
	validToken, _ := generateJWT(testUser)

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
			handler := jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
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
	handler := contextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ContextKeyRequestId) == nil {
			t.Error("Request ID not set in context")
		}
		if r.Context().Value(ContextKeyIPAddress) == nil {
			t.Error("IP address not set in context")
		}
		if r.Context().Value(ContextKeyPath) == nil {
			t.Error("Path not set in context")
		}
		if r.Context().Value(ContextKeyMethod) == nil {
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
	setupTestConfig()

	w := httptest.NewRecorder()
	ctx := context.Background()

	writeErrorResponse(ctx, w, http.StatusBadRequest, ErrorInvalidJson, "Test error message")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var response ErrorResponse
	json.NewDecoder(w.Body).Decode(&response)

	if response.Error != ErrorInvalidJson {
		t.Errorf("Expected error code %s, got %s", ErrorInvalidJson, response.Error)
	}

	if response.Message != "Test error message" {
		t.Errorf("Expected message 'Test error message', got '%s'", response.Message)
	}
}

func TestWriteSuccessResponse(t *testing.T) {
	setupTestConfig()

	w := httptest.NewRecorder()
	ctx := context.Background()
	testData := map[string]string{"test": "data"}

	writeSuccessResponse(ctx, w, testData, http.StatusCreated)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var response SuccessResponse
	json.NewDecoder(w.Body).Decode(&response)

	if response.Message != ResponseSuccess {
		t.Errorf("Expected message %s, got %s", ResponseSuccess, response.Message)
	}
}

// Integration test
func TestUserPasswordFlow(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	// 1. Create user
	createUserReq := CreateUserRequest{
		Username: "integrationuser",
		Password: "IntegrationTest123!",
	}

	body, _ := json.Marshal(createUserReq)
	req := httptest.NewRequest("POST", "/user/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	createUser(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create user: status %d", w.Code)
	}

	// 2. Login user
	loginReq := LoginRequest{
		Username: "integrationuser",
		Password: "IntegrationTest123!",
	}

	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/user/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	loginUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login user: status %d", w.Code)
	}

	var loginResponse SuccessResponse
	var loginData LoginSuccess
	json.NewDecoder(w.Body).Decode(&loginResponse)
	dataBytes, _ := json.Marshal(loginResponse.Data)
	json.Unmarshal(dataBytes, &loginData)

	token := loginData.Token

	// 3. Add password
	value := make([]byte, 256)
	iv := make([]byte, 12)
	authTag := make([]byte, 16)
	salt := make([]byte, 16)

	addPasswordReq := AddPasswordRequest{
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

	jwtMiddleware(addPassword)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to add password: status %d", w.Code)
	}

	// 4. Get passwords
	req = httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwtMiddleware(getPasswords)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get passwords: status %d", w.Code)
	}

	var getPasswordsResponse SuccessResponse
	var passwordsData GetPasswordsSuccess
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
	updatePasswordReq := UpdatePasswordRequest{
		AddPasswordRequest: AddPasswordRequest{
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

	jwtMiddleware(updatePassword)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to update password: status %d", w.Code)
	}

	// 6. Delete password
	deletePasswordReq := DeletePasswordRequest{
		Name: "updated-testsite",
	}

	body, _ = json.Marshal(deletePasswordReq)
	req = httptest.NewRequest("DELETE", "/password/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwtMiddleware(deletePassword)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to delete password: status %d", w.Code)
	}

	// 7. Verify password is deleted
	req = httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	jwtMiddleware(getPasswords)(w, req)

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
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	token, _ := generateJWT(testUser)

	deletePasswordReq := DeletePasswordRequest{
		Name: "nonexistent",
	}

	body, _ := json.Marshal(deletePasswordReq)
	req := httptest.NewRequest("DELETE", "/password/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwtMiddleware(deletePassword)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestUpdatePasswordNotFound(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	token, _ := generateJWT(testUser)

	value := make([]byte, 256)
	iv := make([]byte, 12)
	authTag := make([]byte, 16)
	salt := make([]byte, 16)

	updatePasswordReq := UpdatePasswordRequest{
		AddPasswordRequest: AddPasswordRequest{
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

	jwtMiddleware(updatePassword)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeleteUserSuccess(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	token, _ := generateJWT(testUser)

	req := httptest.NewRequest("DELETE", "/user/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwtMiddleware(deleteUser)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user is deleted
	var user User
	result := testDB.Where("id = ?", testUser.ID).First(&user)
	if result.RowsAffected != 0 {
		t.Error("User should be deleted but still exists")
	}
}

func TestUpdateUserSuccess(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	token, _ := generateJWT(testUser)

	updateUserReq := UpdateUserRequest{
		Username: "updateduser",
		Password: "UpdatedPassword123!",
	}

	body, _ := json.Marshal(updateUserReq)
	req := httptest.NewRequest("PUT", "/user/update", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	jwtMiddleware(updateUser)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user is updated
	var user User
	testDB.Where("id = ?", testUser.ID).First(&user)
	if user.Username != "updateduser" {
		t.Errorf("Expected username 'updateduser', got '%s'", user.Username)
	}

	// Verify password is updated
	if !checkPasswordHash("UpdatedPassword123!", user.PasswordHash) {
		t.Error("Password was not updated correctly")
	}
}

func TestInvalidJSONRequests(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	testUser := createTestUser(t, testDB, "testuser", "ValidPassword123!")
	token, _ := generateJWT(testUser)

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
			handler: createUser,
			method:  "POST",
			path:    "/user/register",
			body:    `{"invalid": json}`,
			useAuth: false,
		},
		{
			name:    "Login with invalid JSON",
			handler: loginUser,
			method:  "POST",
			path:    "/user/login",
			body:    `{"invalid": json}`,
			useAuth: false,
		},
		{
			name:    "Add password with invalid JSON",
			handler: jwtMiddleware(addPassword),
			method:  "POST",
			path:    "/password/create",
			body:    `{"invalid": json}`,
			useAuth: true,
		},
		{
			name:    "Update user with invalid JSON",
			handler: jwtMiddleware(updateUser),
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

			var errorResp ErrorResponse
			json.NewDecoder(w.Body).Decode(&errorResp)
			if errorResp.Error != ErrorInvalidJson {
				t.Errorf("Expected error code %s, got %s", ErrorInvalidJson, errorResp.Error)
			}
		})
	}
}

func TestPasswordIsolationBetweenUsers(t *testing.T) {
	setupTestConfig()
	testDB := setupTestDB(t)
	db = testDB

	// Create two users
	user1 := createTestUser(t, testDB, "user1", "ValidPassword123!")
	user2 := createTestUser(t, testDB, "user2", "ValidPassword123!")

	// Create passwords for both users
	createTestPassword(t, testDB, user1.ID, "user1password")
	createTestPassword(t, testDB, user2.ID, "user2password")

	// Get passwords for user1
	token1, _ := generateJWT(user1)
	req := httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()

	jwtMiddleware(getPasswords)(w, req)

	var response SuccessResponse
	var passwordsData GetPasswordsSuccess
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
	token2, _ := generateJWT(user2)
	req = httptest.NewRequest("GET", "/password", nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w = httptest.NewRecorder()

	jwtMiddleware(getPasswords)(w, req)

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
		_, _ = hashPassword(password)
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, _ := hashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = checkPasswordHash(password, hash)
	}
}

func BenchmarkGenerateJWT(b *testing.B) {
	setupTestConfig()
	user := User{Username: "benchuser"}
	user.ID = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = generateJWT(user)
	}
}

func BenchmarkValidateJWT(b *testing.B) {
	setupTestConfig()
	user := User{Username: "benchuser"}
	user.ID = 1
	token, _ := generateJWT(user)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validateJWT(token)
	}
}
