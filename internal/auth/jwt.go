package auth

import (
	"errors"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	config *config.Config
}

func NewJWTService(cfg *config.Config) *JWTService {
	return &JWTService{config: cfg}
}

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

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}
