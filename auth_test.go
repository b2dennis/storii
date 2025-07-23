package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateJWTValidInput(t *testing.T) {
	config.JWTExpiry = time.Hour * 24
	config.JWTSecret = "test"

	user := User{
		Username: "TestUser",
	}
	user.ID = 1

	_, err := generateJWT(user)

	if err != nil {
		t.Error("generateJWT function returns error with valid input")
	}
}

func TestValidateJWTValid(t *testing.T) {
	config.JWTExpiry = time.Hour * 24
	config.JWTSecret = "test"

	user := User{
		Username: "TestUser",
	}
	user.ID = 1

	token, err := generateJWT(user)

	if err != nil {
		t.Error("generateJWT function returns error with valid input")
		return
	}

	claims, err := validateJWT(token)

	if err != nil {
		t.Error("validateJWT function returns error with valid input")
		return
	}

	if claims.Username != "TestUser" || claims.UserID != 1 {
		t.Error("Recoverd claims don't contain right values")
		return
	}
}

func TestValidateJWTExpired(t *testing.T) {
	config.JWTExpiry = time.Hour * -24
	config.JWTSecret = "test"

	user := User{
		Username: "TestUser",
	}
	user.ID = 1

	token, err := generateJWT(user)

	if err != nil {
		t.Error("validateJWT function returns error with valid input")
		return
	}

	_, err = validateJWT(token)

	if err == nil {
		t.Error("validateJWT function doesn't return an error with an expired token")
		return
	}
}

func TestHashPassword(t *testing.T) {
	password := "TestPassword"

	_, err := hashPassword(password)
	if err != nil {
		t.Error("hashPassword function returns error with valid input")
		return
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "TestPassword"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Error("can't hash test password???")
		return
	}

	if !checkPasswordHash(password, string(hash)) {
		t.Error("checkPasswordHash returns false with correct password")
		return
	}
}
