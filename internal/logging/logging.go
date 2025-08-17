package logging

import (
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/models"
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
