package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateJWT(user User) (string, error) {
	expirationTime := time.Now().Add(config.JWTExpiry)
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.JWTSecret))
}

func validateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return []byte(config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New(ErrorInvalidToken)
	}

	return claims, nil
}

func extractJWTFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New(ErrorAuthHeaderMissing)
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New(ErrorAuthHeaderInvalid)
	}

	return parts[1], nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := extractJWTFromHeader(r)
		if err != nil {
			writeErrorResponse(r.Context(), w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
			return
		}

		claims, err := validateJWT(tokenString)
		if err != nil {
			writeErrorResponse(r.Context(), w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), ContextKeyUserID, claims.UserID))
		r = r.WithContext(context.WithValue(r.Context(), ContextKeyUsername, claims.Username))

		r.Header.Set(AuthHeaderUserID, strconv.FormatUint(uint64(claims.UserID), 10))
		r.Header.Set(AuthHeaderUsername, claims.Username)

		next.ServeHTTP(w, r)
	})
}
