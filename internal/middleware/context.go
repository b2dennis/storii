package middleware

import (
	"b2dennis/pwman-api/internal/constants"
	"context"
	"net/http"

	"github.com/google/uuid"
)

func ContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestId := uuid.New()

		ctx := context.WithValue(r.Context(), constants.ContextKeyRequestId, requestId)
		ctx = context.WithValue(ctx, constants.ContextKeyIPAddress, r.RemoteAddr)
		ctx = context.WithValue(ctx, constants.ContextKeyPath, r.URL.Path)
		ctx = context.WithValue(ctx, constants.ContextKeyMethod, r.Method)

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
