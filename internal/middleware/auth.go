package middleware

import (
	"b2dennis/pwman-api/internal/auth"
	"b2dennis/pwman-api/internal/constants"
	"b2dennis/pwman-api/internal/utils"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type JWT struct {
	jwtService     *auth.JWTService
	responseWriter *utils.ResponseWriter
}

func NewJWT(jwtService *auth.JWTService, responseWriter *utils.ResponseWriter) *JWT {
	return &JWT{
		jwtService:     jwtService,
		responseWriter: responseWriter,
	}
}

func ExtractJWTFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New(constants.ErrorAuthHeaderMissing)
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New(constants.ErrorAuthHeaderInvalid)
	}

	return parts[1], nil
}

func (j *JWT) JwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := ExtractJWTFromHeader(r)
		if err != nil {
			j.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
			return
		}

		claims, err := j.jwtService.ValidateJWT(tokenString)
		if err != nil {
			j.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUserID, claims.UserID))
		r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUsername, claims.Username))

		r.Header.Set(constants.AuthHeaderUserID, strconv.FormatUint(uint64(claims.UserID), 10))
		r.Header.Set(constants.AuthHeaderUsername, claims.Username)

		next.ServeHTTP(w, r)
	})
}
