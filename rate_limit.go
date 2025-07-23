package main

import (
	"net/http"

	"golang.org/x/time/rate"
)

var limitMap map[string]*rate.Limiter = make(map[string]*rate.Limiter)

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		limiter, ok := limitMap[ip]
		if !ok {
			limiter = rate.NewLimiter(rate.Limit(5), 1)
		}

		if !limiter.Allow() {
			writeErrorResponse(w, http.StatusTooManyRequests, ErrorRateLimit)
			return
		}

		next.ServeHTTP(w, r)
	})
}
