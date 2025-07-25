package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

func contextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestId := uuid.New()

		ctx := context.WithValue(r.Context(), ContextKeyRequestId, requestId)
		ctx = context.WithValue(ctx, ContextKeyIPAddress, r.RemoteAddr)
		ctx = context.WithValue(ctx, ContextKeyPath, r.URL.Path)
		ctx = context.WithValue(ctx, ContextKeyMethod, r.Method)

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

var handlerOptions *slog.HandlerOptions = &slog.HandlerOptions{
	AddSource: true,
}
var contextLogger *slog.Logger = slog.New(&ContextHandler{
	slog.NewTextHandler(os.Stdout, handlerOptions),
})

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextLogger.InfoContext(r.Context(), MessageNewRequest)

		next.ServeHTTP(w, r)
	})
}

var limitMap map[string]*rate.Limiter = make(map[string]*rate.Limiter)

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		limiter, ok := limitMap[ip]
		if !ok {
			limiter = rate.NewLimiter(rate.Limit(5), 1)
		}

		if !limiter.Allow() {
			contextLogger.WarnContext(r.Context(), MessageRateLimited)
			writeErrorResponse(r.Context(), w, http.StatusTooManyRequests, ErrorRateLimit)
			return
		}

		next.ServeHTTP(w, r)
	})
}
