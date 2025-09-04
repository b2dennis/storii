package auth

import (
	"errors"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Helper struct to keep JWT state.
type JWTService struct {
	config *config.ServerConfig
}

// Constructor for JWTService.
func NewJWTService(cfg *config.ServerConfig) *JWTService {
	return &JWTService{config: cfg}
}

// Generates a new JWT token for a given user.
func (j *JWTService) GenerateJWT(user models.User) (string, error) {
	expirationTime := time.Now().Add(j.config.JWTExpiry)
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.config.JWTSecret))
}

// Validates a given JWT tokenString.
func (j *JWTService) ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return []byte(j.config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New(constants.ErrorInvalidToken)
	}

	return claims, nil
}

// Additional information for JWT validation.
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}
