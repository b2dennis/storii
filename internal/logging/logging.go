package logging

import (
	"log/slog"

	"github.com/b2dennis/storii/internal/models"
  "github.com/b2dennis/storii/internal/config"
)

var handlerOptions *slog.HandlerOptions = &slog.HandlerOptions{
	AddSource: true,
}

func NewLogger(conf *config.ServerConfig) *slog.Logger {
	return slog.New(&models.ContextHandler{
		Handler: slog.NewTextHandler(conf.LogOutput, handlerOptions),
	})
}
