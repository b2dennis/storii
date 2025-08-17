package models

import (
	"context"
	"github.com/b2dennis/stori/internal/constants"
	"log/slog"
)

type ContextHandler struct {
	Handler slog.Handler
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Handler.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, record slog.Record) error {
	if requestId := ctx.Value(constants.ContextKeyRequestId); requestId != nil {
		record.AddAttrs(slog.Any(constants.ContextKeyRequestId, requestId))
	}
	if ipAddress := ctx.Value(constants.ContextKeyIPAddress); ipAddress != nil {
		record.AddAttrs(slog.String(constants.ContextKeyIPAddress, ipAddress.(string)))
	}
	if path := ctx.Value(constants.ContextKeyPath); path != nil {
		record.AddAttrs(slog.String(constants.ContextKeyPath, path.(string)))
	}
	if method := ctx.Value(constants.ContextKeyMethod); method != nil {
		record.AddAttrs(slog.String(constants.ContextKeyMethod, method.(string)))
	}
	if userId := ctx.Value(constants.ContextKeyUserID); userId != nil {
		record.AddAttrs(slog.Uint64(constants.ContextKeyUserID, uint64(userId.(uint))))
	}
	if username := ctx.Value(constants.ContextKeyUsername); username != nil {
		record.AddAttrs(slog.String(constants.ContextKeyUsername, username.(string)))
	}

	return h.Handler.Handle(ctx, record)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithGroup(name)}
}
