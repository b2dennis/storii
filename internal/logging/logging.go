package logging

import (
	"b2dennis/pwman-api/internal/config"
	"b2dennis/pwman-api/internal/models"
	"log/slog"
)

var handlerOptions *slog.HandlerOptions = &slog.HandlerOptions{
	AddSource: true,
}

func NewLogger(conf *config.Config) *slog.Logger {
	return slog.New(&models.ContextHandler{
		Handler: slog.NewTextHandler(conf.LogOutput, handlerOptions),
	})
}
