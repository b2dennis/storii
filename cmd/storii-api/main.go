// Command storii-api is the storii v2 server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/server"
	"github.com/b2dennis/storii/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if os.Getenv("LOGOUTPUT") == "stderr" {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	h := server.New(db, server.Config{Secret: cfg.Secret, SessionTTL: cfg.SessionTTL, Registration: cfg.Registration,
		TrustProxy: cfg.TrustProxy, AuthRate: 1, AuthBurst: 10}, log)
	srv := &http.Server{Addr: cfg.Address, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	log.Info("listening", "address", cfg.Address, "registration", cfg.Registration)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
