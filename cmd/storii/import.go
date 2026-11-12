package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/importer"
)

// cmdImport brings logins over from a CSV export (Google Password Manager, Chrome, Firefox, Bitwarden, 1Password),
// everything (logins, 2FA codes, cards, passkeys) from a Bitwarden JSON export, logins, 2FA codes and cards from a
// 1Password .1pux export, and 2FA secrets from Authy exports
// or lists of otpauth:// URIs.
func cmdImport(ctx context.Context, v *client.Vault, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "list what would happen, but don't upload")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, "storii import FILE [--dry-run]"); err != nil {
		return err
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var plan importer.Plan
	rows := 0
	if kind := importer.Detect(data); kind == importer.KindBitwarden || kind == importer.KindOnePassword {
		parse := importer.ParseBitwarden
		if kind == importer.KindOnePassword {
			parse = importer.ParseOnePassword
		}
		b, err := parse(data)
		if err != nil {
			return err
		}
		for _, f := range b.Failed {
			fmt.Printf("  could not read: %s\n", f)
		}
		rows, plan = b.Count(), b.Build(v.Items, uuid.NewString, time.Now())
	} else if kind == importer.KindLogins {
		logins, err := importer.ParseCSV(bytes.NewReader(data))
		if err != nil {
			return err
		}
		rows, plan = len(logins), importer.Build(v.Items, logins, uuid.NewString, time.Now())
	} else {
		pw := os.Getenv("STORII_AUTHY_PASSWORD")
		if kind == importer.KindAuthy && pw == "" {
			fmt.Fprintln(os.Stderr, "This is an Authy export, encrypted with your Authy backup password.")
			if pw, err = promptHidden("Authy backup password: "); err != nil {
				return err
			}
		}
		codes, failed, err := importer.ParseOTP(data, pw)
		for _, f := range failed {
			fmt.Printf("  could not read: %s\n", f)
		}
		if err != nil {
			return err
		}
		rows, plan = len(codes), importer.BuildOTP(v.Items, codes, uuid.NewString, time.Now())
	}
	for _, l := range plan.Lines {
		site := ""
		if l.Site != "" && l.Site != l.Name {
			site = "  (" + l.Site + ")"
		}
		switch l.Action {
		case importer.Add:
			note := ""
			if l.Differs {
				note = "  — a different password for this login is already saved; both are kept"
			}
			fmt.Printf("  add       %s%s%s\n", l.Name, site, note)
		case importer.Username:
			fmt.Printf("  username  %s%s\n", l.Name, site)
		case importer.Invalid:
			fmt.Printf("  no password, skipped: %s\n", l.Name)
		}
	}
	added, users, skipped := plan.Count(importer.Add), plan.Count(importer.Username), plan.Count(importer.Skip)
	fmt.Printf("%d entries: %d new, %d usernames filled in, %d already saved.\n", rows, added, users, skipped)
	if *dry || len(plan.Writes) == 0 {
		fmt.Println("Nothing uploaded.")
		return nil
	}
	if _, err := v.Put(ctx, plan.Writes); err != nil {
		return err
	}
	fmt.Printf("Imported. Delete %s now: it holds your secrets.\n", pos[0])
	return nil
}
