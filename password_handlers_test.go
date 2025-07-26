package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestGetPasswords(t *testing.T) {
	config.JWTSecret = "test"
	config.JWTExpiry = time.Hour * 24
	config.LogOutput = bytes.NewBuffer([]byte{})

	initLogger()

	db, _ = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})

	db.AutoMigrate(&User{}, &StoredPassword{})

	passwordHash, _ := hashPassword("*TestPassword1234")

	testUser := User{
		Username:     "TestUser",
		PasswordHash: passwordHash,
	}

	db.Create(&testUser)

	testPassword := StoredPassword{
		UserID:        testUser.ID,
		Name:          "TestPassword",
		Value:         make([]byte, 256),
		IV:            make([]byte, 12),
		AuthTag:       make([]byte, 16),
		Salt:          make([]byte, 16),
		AssociatedURL: "testurl.com",
	}

	db.Create(&testPassword)

	jwtToken, _ := generateJWT(testUser)

	w := httptest.NewRecorder()

	r := httptest.NewRequest("GET", "/password/", nil)
	r.Header.Add("Authorization", "Bearer "+jwtToken)

	jwtMiddleware(getPasswords)(w, r)

	var response GetPasswordTest

	json.NewDecoder(w.Body).Decode(&response)

	if len(response.Data.Passwords) < 1 {
		t.Error("Fetching passwords returned no data")
	} else if response.Data.Passwords[0].Name != "TestPassword" {
		t.Error("Fetching passwords returned false data")
	}
}
