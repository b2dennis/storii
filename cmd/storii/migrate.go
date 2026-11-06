package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/legacy"
	"github.com/b2dennis/storii/internal/vault"
)

// v1Config is the v1 CLI's config file. It holds the master password in plaintext.
type v1Config struct {
	Remote   string `json:"api_address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func v1ConfigPath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "storii", "config.json")
	case "linux":
		return filepath.Join(home, ".config", "storii", "config.json")
	}
	return filepath.Join(home, ".storii")
}

func cmdMigrate(ctx context.Context, v *client.Vault, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dsn := fs.String("legacy-db", "", "Postgres URL of the v1 database")
	server := fs.String("legacy-server", "", "URL of the v1 server")
	user := fs.String("legacy-user", "", "v1 username")
	dry := fs.Bool("dry-run", false, "decrypt and list, but don't upload")
	overwrite := fs.Bool("overwrite", false, "replace entries migrated before (and edited since)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	var old v1Config
	if raw, err := os.ReadFile(v1ConfigPath()); err == nil && json.Unmarshal(raw, &old) == nil {
		fmt.Fprintf(os.Stderr, "Found the v1 config in %s.\n", v1ConfigPath())
		if *user == "" {
			*user = old.Username
		}
		if *dsn == "" && *server == "" {
			*server = old.Remote
		}
	}
	if (*dsn == "") == (*server == "") || *user == "" {
		return errors.New("usage: storii migrate (--legacy-db POSTGRES_URL | --legacy-server URL) --legacy-user NAME")
	}
	pw := old.Password
	if pw == "" || old.Username != *user {
		var err error
		if pw, err = promptHidden("v1 master password for " + *user + ": "); err != nil {
			return err
		}
	}

	var pws []legacy.Password
	var err error
	if *dsn != "" {
		pws, err = legacy.FromDB(ctx, *dsn, *user)
	} else {
		pws, err = legacy.FromServer(ctx, *server, *user, pw)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Decrypting %d v1 passwords…\n", len(pws))
	res := legacy.Convert(*user, pws, pw, time.Now())
	for name, err := range res.Failed {
		fmt.Printf("  could not decrypt %q: %v\n", name, err)
	}
	if len(res.Failed) == len(pws) && len(pws) > 0 {
		return errors.New("nothing could be decrypted; is that the right v1 master password?")
	}

	toWrite := map[string]vault.Item{}
	skipped := 0
	for id, it := range res.Items {
		if _, exists := v.Items[id]; exists && !*overwrite {
			skipped++
			continue
		}
		toWrite[id] = it
	}
	var names []string
	for _, it := range toWrite {
		if it.Kind == vault.KindSecret {
			line := it.Name
			if len(it.Contexts) > 0 {
				line += "  → " + res.Items[it.Contexts[0]].Name
			}
			names = append(names, line)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		fmt.Println("  " + n)
	}
	if skipped > 0 {
		fmt.Printf("%d items were migrated before and are left alone (--overwrite replaces them).\n", skipped)
	}
	if *dry || len(toWrite) == 0 {
		fmt.Println("Nothing uploaded.")
		return nil
	}
	if _, err := v.Put(ctx, toWrite); err != nil {
		return err
	}
	fmt.Printf("Migrated %d passwords (%d new items in total).\n", len(names), len(toWrite))
	if old.Password != "" {
		fmt.Printf("The v1 config %s holds your old master password in plaintext; delete it once you're done with v1.\n", v1ConfigPath())
	}
	return nil
}
