package middleware

import (
	"b2dennis/pwman-api/internal/constants"
	"log/slog"
	"net/http"
)

var handlerOptions *slog.HandlerOptions = &slog.HandlerOptions{
	AddSource: true,
}

var contextLogger *slog.Logger

func initLogger() {
	contextLogger = slog.New(&ContextHandler{
		slog.NewTextHandler(config.LogOutput, handlerOptions),
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextLogger.InfoContext(r.Context(), constants.MessageNewRequest)

		next.ServeHTTP(w, r)
	})
}
