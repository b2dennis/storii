package main

import (
	"log/slog"
	"os"
)

var handlerOptions *slog.HandlerOptions = &slog.HandlerOptions{
	AddSource: true,
}
var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, handlerOptions))
