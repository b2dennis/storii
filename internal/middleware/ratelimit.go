package middleware

import (
	"github.com/b2dennis/stori/internal/constants"
	"github.com/b2dennis/stori/internal/utils"
	"log/slog"
	"net/http"

	"golang.org/x/time/rate"
)

type RateLimit struct {
	logger         *slog.Logger
	responseWriter *utils.ResponseWriter
}

func NewRateLimit(logger *slog.Logger, responseWriter *utils.ResponseWriter) *RateLimit {
	return &RateLimit{
		logger:         logger,
		responseWriter: responseWriter,
	}
}

var limitMap map[string]*rate.Limiter = make(map[string]*rate.Limiter)

func (rl *RateLimit) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		limiter, ok := limitMap[ip]
		if !ok {
			limiter = rate.NewLimiter(rate.Limit(5), 1)
		}

		if !limiter.Allow() {
			rl.logger.WarnContext(r.Context(), constants.MessageRateLimited)
			rl.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusTooManyRequests, constants.ErrorRateLimit)
			return
		}

		next.ServeHTTP(w, r)
	})
}
