package middleware

import (
	"b2dennis/pwman-api/internal/constants"
	"log/slog"
	"net/http"
)

type Log struct {
	logger *slog.Logger
}

func NewLog(logger *slog.Logger) *Log {
	return &Log{
		logger: logger,
	}
}

func (l *Log) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.logger.InfoContext(r.Context(), constants.MessageNewRequest)

		next.ServeHTTP(w, r)
	})
}
