package middleware

import (
	"context"
	"github.com/b2dennis/stori/internal/constants"
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
