// Command storii-devserver runs the API against a throwaway local Postgres for client development:
// go run ./cmd/storii-devserver (Android emulator: http://10.0.2.2:9999 or adb reverse).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/b2dennis/storii/internal/server"
	"github.com/b2dennis/storii/internal/store"
)

func main() {
	dataDir := flag.String("data", filepath.Join(os.TempDir(), "storii-dev"), "where the dev database lives (kept between runs)")
	addr := flag.String("addr", ":9999", "listen address")
	pgPort := flag.Uint("pg-port", 54339, "port for the embedded Postgres")
	flag.Parse()

	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(uint32(*pgPort)).Database("storii").Username("storii").Password("dev").
		DataPath(filepath.Join(*dataDir, "pg")).RuntimePath(filepath.Join(*dataDir, "rt")))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	defer pg.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	db, err := store.Open(ctx, fmt.Sprintf("postgres://storii:dev@localhost:%d/storii?sslmode=disable", *pgPort))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer db.Close()
	h := server.New(db, server.Config{Secret: []byte("dev-secret-dev-secret"), SessionTTL: 30 * 24 * time.Hour,
		Registration: true, AuthRate: 100, AuthBurst: 100}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	srv := &http.Server{Addr: *addr, Handler: h}
	go func() { <-ctx.Done(); srv.Shutdown(context.Background()) }()
	fmt.Printf("storii dev server on http://localhost%s (Postgres on port %d, data in %s)\n", *addr, *pgPort, *dataDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
	}
}
