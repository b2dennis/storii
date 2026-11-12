// Command storii is the command-line client for storii v2.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/vault"
)

const usage = `storii – zero-knowledge secret manager

Account
  storii register [--server URL] [--user NAME]   create an account (and log in)
  storii login [--server URL] [--user NAME]      log in on this machine
  storii logout                                  end this machine's session
  storii passwd                                  change the master password
  storii sessions                                list logged-in devices
  storii sync                                    fetch changes from the server

Secrets (types: password, totp, api_key, note, card)
  storii ls [QUERY] [--type T] [--context NAME] [--site HOST]
  storii show NAME [--reveal]
  storii get NAME [--print]        copy the password / current 2FA code / API key / note
  storii user NAME [--print]       copy the username
  storii totp NAME                 print the current 2FA code
  storii add password NAME [--user U] [--gen [--length N]] [--url URL]... [--context C]...
  storii add totp NAME (--uri otpauth://... | --secret BASE32 [--issuer I] [--account A]) [--url URL]... [--context C]...
  storii add apikey NAME [--key-id ID] [--url URL]... [--context C]...   (prompts for the key)
  storii add note NAME [--context C]...                                  (reads the note from stdin)
  storii add card NAME [--holder NAME] [--expiry MM/YY]                  (prompts for the number and CVC)
  storii edit NAME [--name N] [--user U] [--password] [--gen] [--notes TEXT] [--field K=V]...
                   [--context C]... [--unlink C]...
  storii rm NAME [--yes]
  storii gen [LENGTH] [--no-symbols]

Contexts (apps and websites; a secret can belong to several)
  storii ctx ls
  storii ctx show NAME
  storii ctx add NAME [--url URL]... [--app ANDROID_PACKAGE]... [--type website|app|other]
  storii ctx edit NAME [--name N] [--url URL]... [--app PKG]... [--clear]
  storii ctx rm NAME
  storii ctx link SECRET CONTEXT     storii ctx unlink SECRET CONTEXT

Importing from other password managers
  storii import FILE [--dry-run]    logins from a CSV export of Google Password Manager (passwords.google.com,
                                    Chrome, the Android app), Firefox, Bitwarden or 1Password; 2FA codes from an
                                    Authy export (asks for the Authy backup password) or a list of otpauth:// links;
                                    logins, 2FA codes, cards and passkeys from a Bitwarden JSON export;
                                    logins, 2FA codes and cards from a 1Password .1pux export.
                                    Safe to run twice.

Moving from storii v1
  storii migrate --legacy-db POSTGRES_URL --legacy-user NAME [--dry-run] [--overwrite]
  storii migrate --legacy-server URL --legacy-user NAME [--dry-run] [--overwrite]

--url on secrets creates or reuses a website context for that URL. STORII_PASSWORD supplies the master password
non-interactively (scripts only). State lives in ` + "%s" + `.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "storii:", err)
		os.Exit(1)
	}
}

func statePath() string {
	if p := os.Getenv("STORII_STATE"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "storii", "state.json")
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Printf(usage, statePath())
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "register", "login":
		return cmdLogin(ctx, cmd == "register", rest)
	case "gen":
		return cmdGen(rest)
	case "_clear-clipboard":
		clearClipboardLater(rest)
		return nil
	}
	st, err := client.LoadState(statePath())
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("not logged in; run `storii login` or `storii register`")
	} else if err != nil {
		return err
	}
	if cmd == "logout" {
		if err := st.API().Logout(ctx); err != nil && !client.IsUnauthorized(err) {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
		return os.Remove(statePath())
	}
	// Everything else needs the vault. Pull first; offline is fine for reading.
	pullErr := st.Pull(ctx)
	if client.IsUnauthorized(pullErr) {
		return errors.New("the session has expired or was revoked; run `storii login`")
	}
	if pullErr != nil {
		fmt.Fprintln(os.Stderr, "warning: offline, using the local copy:", pullErr)
	} else if err := st.Save(statePath()); err != nil {
		return err
	}
	if cmd == "sync" {
		fmt.Printf("%d items, revision %d\n", len(st.Items), st.Revision)
		return pullErr
	}
	pw, err := masterPassword("Master password: ")
	if err != nil {
		return err
	}
	v, err := st.Unlock(pw)
	if err != nil {
		return err
	}
	if n := len(v.Undecryptable); n > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d items could not be decrypted\n", n)
	}
	defer st.Save(statePath())
	switch cmd {
	case "ls":
		return cmdList(v, rest)
	case "show":
		return cmdShow(v, rest)
	case "get", "user":
		return cmdGet(v, cmd == "user", rest)
	case "totp":
		return cmdTOTP(v, rest)
	case "add":
		return cmdAdd(ctx, v, rest)
	case "edit":
		return cmdEdit(ctx, v, rest)
	case "rm":
		return cmdRemove(ctx, v, rest)
	case "ctx":
		return cmdContext(ctx, v, rest)
	case "passwd":
		return cmdPasswd(ctx, v)
	case "sessions":
		return cmdSessions(ctx, st)
	case "migrate":
		return cmdMigrate(ctx, v, rest)
	case "import":
		return cmdImport(ctx, v, rest)
	}
	return fmt.Errorf("unknown command %q (try storii help)", cmd)
}

// Flag helpers.

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

// parse allows flags after positional arguments ("storii add password github --user me").
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintf(os.Stderr, "see `storii help`\n") }
	return fs
}

func needArgs(pos []string, n int, what string) error {
	if len(pos) != n {
		return fmt.Errorf("usage: %s", what)
	}
	return nil
}

// Prompts.

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func promptHidden(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return prompt(label)
	}
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func masterPassword(label string) (string, error) {
	if pw := os.Getenv("STORII_PASSWORD"); pw != "" {
		return pw, nil
	}
	return promptHidden(label)
}

func deviceName() string {
	host, _ := os.Hostname()
	return "storii CLI on " + cmpOr(host, runtime.GOOS)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Commands.

func cmdLogin(ctx context.Context, register bool, args []string) error {
	fs := newFlags("login")
	server := fs.String("server", os.Getenv("STORII_SERVER"), "server URL")
	user := fs.String("user", "", "username")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	var err error
	if *server == "" {
		if *server, err = prompt("Server URL: "); err != nil {
			return err
		}
	}
	if *user == "" {
		if *user, err = prompt("Username: "); err != nil {
			return err
		}
	}
	pw, err := masterPassword("Master password: ")
	if err != nil {
		return err
	}
	var st *client.State
	var v *client.Vault
	if register {
		if msg := passwordProblem(pw); msg != "" {
			return errors.New(msg)
		}
		if os.Getenv("STORII_PASSWORD") == "" {
			again, err := promptHidden("Repeat master password: ")
			if err != nil {
				return err
			}
			if again != pw {
				return errors.New("the passwords don't match")
			}
		}
		fmt.Fprintln(os.Stderr, "There is no way to recover a forgotten master password. Write it down somewhere safe.")
		st, v, err = client.Register(ctx, *server, *user, pw, deviceName())
	} else {
		st, v, err = client.Login(ctx, *server, *user, pw, deviceName())
	}
	if err != nil {
		return err
	}
	if err := st.Save(statePath()); err != nil {
		return err
	}
	fmt.Printf("Logged in as %s on %s: %d secrets, %d contexts.\n", st.Username, st.Server,
		len(v.List(vault.KindSecret)), len(v.List(vault.KindContext)))
	return nil
}

// passwordProblem applies v1's rule: 12+ characters with three of upper, lower, digit, symbol.
func passwordProblem(pw string) string {
	classes := 0
	for _, f := range []func(rune) bool{
		func(r rune) bool { return r >= 'a' && r <= 'z' }, func(r rune) bool { return r >= 'A' && r <= 'Z' },
		func(r rune) bool { return r >= '0' && r <= '9' },
		func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') },
	} {
		if strings.ContainsFunc(pw, f) {
			classes++
		}
	}
	if len([]rune(pw)) < 12 || classes < 3 {
		return "the master password needs at least 12 characters and three of: lowercase, uppercase, digits, symbols"
	}
	return ""
}

func cmdGen(args []string) error {
	fs := newFlags("gen")
	noSym := fs.Bool("no-symbols", false, "letters and digits only")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	n := 24
	if len(pos) == 1 {
		if _, err := fmt.Sscan(pos[0], &n); err != nil {
			return errors.New("length must be a number")
		}
	}
	fmt.Println(vault.GeneratePassword(n, !*noSym))
	return nil
}

func typeLabel(t string) string {
	switch t {
	case vault.TypePassword:
		return "password"
	case vault.TypeTOTP:
		return "2fa"
	case vault.TypeAPIKey:
		return "api key"
	case vault.TypeNote:
		return "note"
	case vault.TypeCard:
		return "card"
	case vault.TypePasskey:
		return "passkey"
	}
	return t
}

func contextNames(v *client.Vault, ids []string) string {
	var names []string
	for _, id := range ids {
		if c, ok := v.Items[id]; ok {
			names = append(names, c.Name)
		}
	}
	return strings.Join(names, ", ")
}

func cmdList(v *client.Vault, args []string) error {
	fs := newFlags("ls")
	typ := fs.String("type", "", "only this type")
	ctxName := fs.String("context", "", "only secrets in this context")
	site := fs.String("site", "", "only secrets for this website host")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	entries := v.List(vault.KindSecret)
	if *site != "" {
		entries = v.ForSite(*site, "")
	}
	var ctxID string
	if *ctxName != "" {
		c, err := v.Find(vault.KindContext, *ctxName)
		if err != nil {
			return err
		}
		ctxID = c.ID
	}
	q := strings.ToLower(strings.Join(pos, " "))
	for _, e := range entries {
		if *typ != "" && e.Type != strings.ReplaceAll(*typ, "apikey", vault.TypeAPIKey) {
			continue
		}
		if ctxID != "" && !slices.Contains(e.Contexts, ctxID) {
			continue
		}
		names := contextNames(v, e.Contexts)
		if q != "" && !strings.Contains(strings.ToLower(e.Name+" "+names+" "+e.Field(vault.FieldUsername)), q) {
			continue
		}
		line := fmt.Sprintf("%s  %-9s %s", e.ID[:8], typeLabel(e.Type), e.Name)
		switch {
		case e.Field(vault.FieldUsername) != "":
			line += "  (" + e.Field(vault.FieldUsername) + ")"
		case e.Type == vault.TypeCard && e.Field(vault.FieldNumber) != "":
			line += "  " + vault.CardMasked(e.Field(vault.FieldNumber))
		case e.Type == vault.TypePasskey && e.Field("user_name") != "":
			line += "  (" + e.Field("user_name") + ")"
		}
		if names != "" {
			line += "  [" + names + "]"
		}
		fmt.Println(line)
	}
	return nil
}

func cmdShow(v *client.Vault, args []string) error {
	fs := newFlags("show")
	reveal := fs.Bool("reveal", false, "show hidden values")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, "storii show NAME [--reveal]"); err != nil {
		return err
	}
	e, err := v.Find(vault.KindSecret, pos[0])
	if err != nil {
		return err
	}
	mask := func(s string) string {
		if *reveal || s == "" {
			return s
		}
		return "•••••••• (--reveal)"
	}
	fmt.Printf("%s (%s, id %s)\n", e.Name, typeLabel(e.Type), e.ID)
	switch e.Type {
	case vault.TypePassword:
		fmt.Printf("  username: %s\n  password: %s\n", e.Field(vault.FieldUsername), mask(e.Field(vault.FieldPassword)))
	case vault.TypeTOTP:
		t, err := vault.TOTPFromFields(e.Fields)
		if err == nil {
			now := time.Now()
			fmt.Printf("  code:     %s (%ds left)\n", t.Code(now), int(t.Remaining(now).Seconds()))
			fmt.Printf("  issuer:   %s\n  account:  %s\n", t.Issuer, t.Account)
			if *reveal {
				fmt.Printf("  uri:      %s\n", t.URI())
			}
		}
	case vault.TypeAPIKey:
		if id := e.Field(vault.FieldKeyID); id != "" {
			fmt.Printf("  key id:   %s\n", id)
		}
		fmt.Printf("  key:      %s\n", mask(e.Field(vault.FieldKey)))
	case vault.TypePasskey:
		fmt.Printf("  website:  %s\n  account:  %s\n", e.Field("rp_id"), e.Field("user_name"))
	case vault.TypeCard:
		num := vault.CardMasked(e.Field(vault.FieldNumber))
		if *reveal {
			num = e.Field(vault.FieldNumber)
		}
		if b := vault.CardBrand(e.Field(vault.FieldNumber)); b != "" {
			num += " (" + b + ")"
		}
		fmt.Printf("  holder:   %s\n  number:   %s\n  expiry:   %s\n  cvc:      %s\n", e.Field(vault.FieldCardholder), num,
			e.Field(vault.FieldExpiry), mask(e.Field(vault.FieldCVC)))
	}
	known := map[string]bool{vault.FieldUsername: true, vault.FieldPassword: true, vault.FieldSecret: true,
		vault.FieldIssuer: true, vault.FieldAccount: true, vault.FieldAlgorithm: true, vault.FieldDigits: true,
		vault.FieldPeriod: true, vault.FieldKey: true, vault.FieldKeyID: true, vault.FieldCardholder: true,
		vault.FieldNumber: true, vault.FieldExpiry: true, vault.FieldCVC: true, "credential_id": true, "rp_id": true,
		"user_handle": true, "user_name": true, "user_display_name": true, "private_key": true}
	for k, val := range e.Fields {
		if !known[k] {
			fmt.Printf("  %s: %s\n", k, val)
		}
	}
	for _, c := range e.Custom {
		val := c.Value
		if c.Hidden {
			val = mask(val)
		}
		fmt.Printf("  %s: %s\n", c.Name, val)
	}
	for _, id := range e.Contexts {
		if c, ok := v.Items[id]; ok {
			fmt.Printf("  context:  %s %s\n", c.Name, strings.Join(append(c.URLs, c.AndroidPackages...), " "))
		}
	}
	if e.Notes != "" {
		fmt.Printf("  notes:\n    %s\n", strings.ReplaceAll(e.Notes, "\n", "\n    "))
	}
	fmt.Printf("  updated:  %s\n", e.UpdatedAt.Local().Format(time.DateTime))
	return nil
}

func cmdGet(v *client.Vault, username bool, args []string) error {
	fs := newFlags("get")
	print := fs.Bool("print", false, "print instead of copying")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, "storii get NAME [--print]"); err != nil {
		return err
	}
	e, err := v.Find(vault.KindSecret, pos[0])
	if err != nil {
		return err
	}
	val, err := e.SecretValue(time.Now())
	what := typeLabel(e.Type)
	if username {
		val, what = e.Field(vault.FieldUsername), "username"
	}
	if err != nil {
		return err
	}
	if val == "" {
		return fmt.Errorf("%s has no %s", e.Name, what)
	}
	if *print || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println(val)
		return nil
	}
	if err := copyToClipboard(val, !username); err != nil {
		fmt.Fprintln(os.Stderr, "no clipboard available:", err)
		fmt.Println(val)
		return nil
	}
	msg := fmt.Sprintf("Copied the %s of %s.", what, e.Name)
	if !username {
		msg += fmt.Sprintf(" The clipboard is cleared in %ds.", clipboardSeconds)
	}
	fmt.Println(msg)
	return nil
}

func cmdTOTP(v *client.Vault, args []string) error {
	if err := needArgs(args, 1, "storii totp NAME"); err != nil {
		return err
	}
	e, err := v.Find(vault.KindSecret, args[0], vault.TypeTOTP)
	if err != nil {
		if e, err = v.Find(vault.KindSecret, args[0]); err != nil {
			return err
		}
	}
	if e.Type != vault.TypeTOTP {
		// A password's context may have a 2FA secret next to it.
		for _, c := range e.Contexts {
			for _, s := range v.List(vault.KindSecret) {
				if s.Type == vault.TypeTOTP && slices.Contains(s.Contexts, c) {
					e = s
				}
			}
		}
		if e.Type != vault.TypeTOTP {
			return fmt.Errorf("%s is not a 2FA secret", e.Name)
		}
	}
	t, err := vault.TOTPFromFields(e.Fields)
	if err != nil {
		return err
	}
	now := time.Now()
	fmt.Printf("%s  (%ds left)\n", t.Code(now), int(t.Remaining(now).Seconds()))
	return nil
}

// contextForURL finds the website context matching a URL exactly by host, or makes one.
func contextForURL(v *client.Vault, raw string, pending map[string]vault.Item) (string, error) {
	host := vault.Host(raw)
	if host == "" {
		return "", fmt.Errorf("%q is not a URL or domain", raw)
	}
	for id, it := range pending {
		if it.Kind == vault.KindContext && slices.ContainsFunc(it.URLs, func(u string) bool { return vault.Host(u) == host }) {
			return id, nil
		}
	}
	for _, c := range v.List(vault.KindContext) {
		if slices.ContainsFunc(c.URLs, func(u string) bool { return vault.Host(u) == host }) {
			return c.ID, nil
		}
	}
	u := raw
	if !strings.Contains(u, "://") {
		u = "https://" + host
	}
	id := "new:" + host
	pending[id] = vault.Item{Kind: vault.KindContext, ContextType: vault.ContextWebsite, Name: host, URLs: []string{u}}
	return id, nil
}

// saveWithContexts uploads a secret plus any new contexts it refers to, fixing up the temporary ids.
func saveWithContexts(ctx context.Context, v *client.Vault, id string, secret vault.Item, pending map[string]vault.Item) (string, error) {
	if len(pending) > 0 {
		var tmp []string
		var items []vault.Item
		for k, it := range pending {
			tmp, items = append(tmp, k), append(items, it)
		}
		for i, it := range items {
			newID, err := v.PutOne(ctx, "", it)
			if err != nil {
				return "", err
			}
			for j, c := range secret.Contexts {
				if c == tmp[i] {
					secret.Contexts[j] = newID
				}
			}
		}
	}
	return v.PutOne(ctx, id, secret)
}

func linkContexts(v *client.Vault, secret *vault.Item, urls, names []string, pending map[string]vault.Item) error {
	for _, u := range urls {
		id, err := contextForURL(v, u, pending)
		if err != nil {
			return err
		}
		if !slices.Contains(secret.Contexts, id) {
			secret.Contexts = append(secret.Contexts, id)
		}
	}
	for _, n := range names {
		c, err := v.Find(vault.KindContext, n)
		if err != nil {
			return err
		}
		if !slices.Contains(secret.Contexts, c.ID) {
			secret.Contexts = append(secret.Contexts, c.ID)
		}
	}
	return nil
}

func cmdAdd(ctx context.Context, v *client.Vault, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: storii add password|totp|apikey|note|card NAME ...")
	}
	typ := args[0]
	fs := newFlags("add")
	var urls, ctxs list
	fs.Var(&urls, "url", "website URL (repeatable)")
	fs.Var(&ctxs, "context", "existing context (repeatable)")
	user := fs.String("user", "", "username")
	gen := fs.Bool("gen", false, "generate the password")
	length := fs.Int("length", 24, "generated password length")
	uri := fs.String("uri", "", "otpauth:// URI")
	secretB32 := fs.String("secret", "", "TOTP secret (base32)")
	issuer := fs.String("issuer", "", "TOTP issuer")
	account := fs.String("account", "", "TOTP account")
	keyID := fs.String("key-id", "", "API key id")
	holder := fs.String("holder", "", "cardholder name")
	expiry := fs.String("expiry", "", "card expiry, MM/YY")
	notes := fs.String("notes", "", "notes")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, "storii add "+typ+" NAME ..."); err != nil {
		return err
	}
	it := vault.Item{Kind: vault.KindSecret, Name: pos[0], Fields: map[string]string{}, Notes: *notes}
	switch typ {
	case "password":
		it.Type = vault.TypePassword
		it.Fields[vault.FieldUsername] = *user
		if *gen {
			it.Fields[vault.FieldPassword] = vault.GeneratePassword(*length, true)
		} else if it.Fields[vault.FieldPassword], err = promptHidden("Password (empty to generate): "); err != nil {
			return err
		} else if it.Fields[vault.FieldPassword] == "" {
			it.Fields[vault.FieldPassword] = vault.GeneratePassword(*length, true)
			*gen = true
		}
	case "totp", "2fa":
		it.Type = vault.TypeTOTP
		var t vault.TOTP
		switch {
		case *uri != "":
			t, err = vault.ParseOTPAuth(*uri)
		case *secretB32 != "":
			t, err = vault.TOTPFromFields(map[string]string{vault.FieldSecret: *secretB32, vault.FieldIssuer: *issuer, vault.FieldAccount: *account})
		default:
			var in string
			if in, err = promptHidden("otpauth:// URI or base32 secret: "); err == nil {
				if strings.HasPrefix(in, "otpauth://") {
					t, err = vault.ParseOTPAuth(in)
				} else {
					t, err = vault.TOTPFromFields(map[string]string{vault.FieldSecret: in, vault.FieldIssuer: *issuer, vault.FieldAccount: *account})
				}
			}
		}
		if err != nil {
			return err
		}
		it.Fields = t.Fields()
	case "apikey", "api_key", "api-key":
		it.Type = vault.TypeAPIKey
		if *keyID != "" {
			it.Fields[vault.FieldKeyID] = *keyID
		}
		if it.Fields[vault.FieldKey], err = promptHidden("API key: "); err != nil {
			return err
		}
	case "note":
		it.Type = vault.TypeNote
		if it.Notes == "" {
			fmt.Fprintln(os.Stderr, "Type the note, end with Ctrl-D:")
			var b strings.Builder
			sc := bufio.NewScanner(stdin)
			for sc.Scan() {
				b.WriteString(sc.Text() + "\n")
			}
			it.Notes = strings.TrimRight(b.String(), "\n")
		}
	case "card":
		it.Type = vault.TypeCard
		it.Fields[vault.FieldCardholder] = *holder
		num, err := promptHidden("Card number: ")
		if err != nil {
			return err
		}
		if !vault.CardValid(num) {
			return errors.New("that card number isn't valid (check for a typo)")
		}
		it.Fields[vault.FieldNumber] = vault.CardDigits(num)
		if *expiry == "" {
			if *expiry, err = prompt("Expiry (MM/YY): "); err != nil {
				return err
			}
		}
		if it.Fields[vault.FieldExpiry] = vault.NormalizeExpiry(*expiry); it.Fields[vault.FieldExpiry] == "" {
			return fmt.Errorf("expiry %q isn't MM/YY", *expiry)
		}
		if it.Fields[vault.FieldCVC], err = promptHidden("CVC (empty if none): "); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown type %q: use password, totp, apikey, note or card", typ)
	}
	pending := map[string]vault.Item{}
	if err := linkContexts(v, &it, urls, ctxs, pending); err != nil {
		return err
	}
	id, err := saveWithContexts(ctx, v, "", it, pending)
	if err != nil {
		return err
	}
	fmt.Printf("Saved %s (%s).\n", it.Name, id[:8])
	if *gen && term.IsTerminal(int(os.Stdout.Fd())) {
		if copyToClipboard(it.Fields[vault.FieldPassword], true) == nil {
			fmt.Println("The generated password is on the clipboard.")
		}
	}
	return nil
}

func cmdEdit(ctx context.Context, v *client.Vault, args []string) error {
	fs := newFlags("edit")
	var urls, ctxs, unlink, fields list
	fs.Var(&urls, "url", "link a website context (repeatable)")
	fs.Var(&ctxs, "context", "link a context (repeatable)")
	fs.Var(&unlink, "unlink", "unlink a context (repeatable)")
	fs.Var(&fields, "field", "set a field, K=V (repeatable; empty V removes it)")
	name := fs.String("name", "", "new name")
	user := fs.String("user", "\x00", "new username")
	newPw := fs.Bool("password", false, "prompt for a new password / key / TOTP secret")
	gen := fs.Bool("gen", false, "generate a new password")
	notes := fs.String("notes", "\x00", "new notes")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, "storii edit NAME [flags]"); err != nil {
		return err
	}
	e, err := v.Find(vault.KindSecret, pos[0])
	if err != nil {
		return err
	}
	it := e.Item
	it.Fields = cloneMap(it.Fields)
	it.Contexts = slices.Clone(it.Contexts)
	if *name != "" {
		it.Name = *name
	}
	if *user != "\x00" {
		it.Fields[vault.FieldUsername] = *user
	}
	if *notes != "\x00" {
		it.Notes = *notes
	}
	if *gen {
		it.Fields[vault.FieldPassword] = vault.GeneratePassword(24, true)
	}
	if *newPw {
		field := map[string]string{vault.TypePassword: vault.FieldPassword, vault.TypeAPIKey: vault.FieldKey,
			vault.TypeTOTP: vault.FieldSecret, vault.TypeCard: vault.FieldNumber}[it.Type]
		if field == "" {
			return errors.New("notes have no secret value; use --notes")
		}
		if it.Fields[field], err = promptHidden("New value: "); err != nil {
			return err
		}
	}
	for _, f := range fields {
		k, val, ok := strings.Cut(f, "=")
		if !ok {
			return errors.New("--field takes K=V")
		}
		if val == "" {
			delete(it.Fields, k)
		} else {
			it.Fields[k] = val
		}
	}
	for _, n := range unlink {
		c, err := v.Find(vault.KindContext, n)
		if err != nil {
			return err
		}
		it.Contexts = slices.DeleteFunc(it.Contexts, func(id string) bool { return id == c.ID })
	}
	pending := map[string]vault.Item{}
	if err := linkContexts(v, &it, urls, ctxs, pending); err != nil {
		return err
	}
	if _, err := saveWithContexts(ctx, v, e.ID, it, pending); err != nil {
		return err
	}
	fmt.Printf("Updated %s.\n", it.Name)
	if *gen && term.IsTerminal(int(os.Stdout.Fd())) && copyToClipboard(it.Fields[vault.FieldPassword], true) == nil {
		fmt.Println("The new password is on the clipboard.")
	}
	return nil
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func confirm(q string) bool {
	a, _ := prompt(q + " [y/N] ")
	return strings.EqualFold(strings.TrimSpace(a), "y")
}

func cmdRemove(ctx context.Context, v *client.Vault, args []string) error {
	fs := newFlags("rm")
	yes := fs.Bool("yes", false, "don't ask")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needArgs(pos, 1, "storii rm NAME [--yes]"); err != nil {
		return err
	}
	e, err := v.Find(vault.KindSecret, pos[0])
	if err != nil {
		return err
	}
	if !*yes && !confirm("Delete "+e.Name+"?") {
		return nil
	}
	if err := v.Delete(ctx, e.ID); err != nil {
		return err
	}
	fmt.Printf("Deleted %s.\n", e.Name)
	return nil
}

func cmdContext(ctx context.Context, v *client.Vault, args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	sub, args := args[0], args[1:]
	fs := newFlags("ctx")
	var urls, apps list
	fs.Var(&urls, "url", "website URL (repeatable)")
	fs.Var(&apps, "app", "Android package name (repeatable)")
	typ := fs.String("type", "", "website, app or other")
	name := fs.String("name", "", "new name")
	clear := fs.Bool("clear", false, "replace the URLs and apps instead of adding")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	switch sub {
	case "ls":
		for _, c := range v.List(vault.KindContext) {
			n := 0
			for _, s := range v.List(vault.KindSecret) {
				if slices.Contains(s.Contexts, c.ID) {
					n++
				}
			}
			fmt.Printf("%s  %-7s %s  %s  (%d secrets)\n", c.ID[:8], c.ContextType, c.Name,
				strings.Join(append(slices.Clone(c.URLs), c.AndroidPackages...), " "), n)
		}
		return nil
	case "show":
		if err := needArgs(pos, 1, "storii ctx show NAME"); err != nil {
			return err
		}
		c, err := v.Find(vault.KindContext, pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s (%s, id %s)\n", c.Name, c.ContextType, c.ID)
		for _, u := range c.URLs {
			fmt.Println("  url:", u)
		}
		for _, a := range c.AndroidPackages {
			fmt.Println("  app:", a)
		}
		for _, s := range v.List(vault.KindSecret) {
			if slices.Contains(s.Contexts, c.ID) {
				fmt.Printf("  secret: %s (%s)\n", s.Name, typeLabel(s.Type))
			}
		}
		return nil
	case "add":
		if err := needArgs(pos, 1, "storii ctx add NAME [--url URL]... [--app PKG]..."); err != nil {
			return err
		}
		t := *typ
		if t == "" {
			t = vault.ContextWebsite
			if len(urls) == 0 && len(apps) > 0 {
				t = vault.ContextApp
			}
		}
		id, err := v.PutOne(ctx, "", vault.Item{Kind: vault.KindContext, Name: pos[0], ContextType: t, URLs: urls, AndroidPackages: apps})
		if err != nil {
			return err
		}
		fmt.Printf("Added context %s (%s).\n", pos[0], id[:8])
		return nil
	case "edit":
		if err := needArgs(pos, 1, "storii ctx edit NAME [flags]"); err != nil {
			return err
		}
		c, err := v.Find(vault.KindContext, pos[0])
		if err != nil {
			return err
		}
		it := c.Item
		if *clear {
			it.URLs, it.AndroidPackages = nil, nil
		}
		it.URLs = append(slices.Clone(it.URLs), urls...)
		it.AndroidPackages = append(slices.Clone(it.AndroidPackages), apps...)
		if *name != "" {
			it.Name = *name
		}
		if *typ != "" {
			it.ContextType = *typ
		}
		if _, err := v.PutOne(ctx, c.ID, it); err != nil {
			return err
		}
		fmt.Printf("Updated context %s.\n", it.Name)
		return nil
	case "rm":
		if err := needArgs(pos, 1, "storii ctx rm NAME"); err != nil {
			return err
		}
		c, err := v.Find(vault.KindContext, pos[0])
		if err != nil {
			return err
		}
		if err := v.Delete(ctx, c.ID); err != nil {
			return err
		}
		fmt.Printf("Deleted context %s (its secrets are kept).\n", c.Name)
		return nil
	case "link", "unlink":
		if err := needArgs(pos, 2, "storii ctx "+sub+" SECRET CONTEXT"); err != nil {
			return err
		}
		s, err := v.Find(vault.KindSecret, pos[0])
		if err != nil {
			return err
		}
		c, err := v.Find(vault.KindContext, pos[1])
		if err != nil {
			return err
		}
		it := s.Item
		it.Contexts = slices.DeleteFunc(slices.Clone(it.Contexts), func(id string) bool { return id == c.ID })
		if sub == "link" {
			it.Contexts = append(it.Contexts, c.ID)
		}
		if _, err := v.PutOne(ctx, s.ID, it); err != nil {
			return err
		}
		fmt.Printf("%sed %s and %s.\n", strings.ToUpper(sub[:1])+sub[1:], s.Name, c.Name)
		return nil
	}
	return fmt.Errorf("unknown ctx command %q", sub)
}

func cmdPasswd(ctx context.Context, v *client.Vault) error {
	pw, err := promptHidden("New master password: ")
	if err != nil {
		return err
	}
	if msg := passwordProblem(pw); msg != "" {
		return errors.New(msg)
	}
	again, err := promptHidden("Repeat: ")
	if err != nil {
		return err
	}
	if again != pw {
		return errors.New("the passwords don't match")
	}
	if err := v.ChangePassword(ctx, pw); err != nil {
		return err
	}
	fmt.Println("Master password changed. Other devices have been logged out.")
	return nil
}

func cmdSessions(ctx context.Context, st *client.State) error {
	var r struct {
		Sessions []struct {
			ID         string    `json:"id"`
			DeviceName string    `json:"device_name"`
			LastUsedAt time.Time `json:"last_used_at"`
			Current    bool      `json:"current"`
		} `json:"sessions"`
	}
	if err := st.API().Get(ctx, "/api/v2/sessions", &r); err != nil {
		return err
	}
	for _, s := range r.Sessions {
		cur := ""
		if s.Current {
			cur = "  (this one)"
		}
		fmt.Printf("%s  %s  last used %s%s\n", s.ID, s.DeviceName, s.LastUsedAt.Local().Format(time.DateTime), cur)
	}
	return nil
}
