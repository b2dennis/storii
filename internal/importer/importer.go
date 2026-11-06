// Package importer brings logins over from other password managers' CSV exports: Google Password Manager
// (passwords.google.com, Chrome, the Android app), Firefox, Bitwarden and 1Password. Each row becomes a password
// secret with a website or Android app context. Rows already in the vault are skipped, and a row that matches a
// login without a username (as storii v1 migrated them) fills that username in, so importing twice is safe.
package importer

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// Row is one login from an export.
type Row struct {
	Name, URL, Username, Password, Note string
}

// Column names per field, as the supported exports spell them (lowercased).
var columns = map[string][]string{
	"name":     {"name", "title"},
	"url":      {"url", "login_uri", "website", "web site"},
	"username": {"username", "login_username", "login"},
	"password": {"password", "login_password"},
	"note":     {"note", "notes", "extra"},
}

// ParseCSV reads an export. The header row decides which column is which.
func ParseCSV(r io.Reader) ([]Row, error) {
	br := bufio.NewReader(r)
	if b, err := br.Peek(3); err == nil && string(b) == "\uFEFF" {
		_, _ = br.Discard(3)
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("reading the header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		for field, names := range columns {
			if _, done := idx[field]; !done && slices.Contains(names, h) {
				idx[field] = i
			}
		}
	}
	if _, ok := idx["password"]; !ok {
		return nil, errors.New("this doesn't look like a password export: no password column")
	}
	var rows []Row
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return rows, nil
		}
		if err != nil {
			return nil, err
		}
		get := func(field string) string {
			if i, ok := idx[field]; ok && i < len(rec) {
				return rec[i]
			}
			return ""
		}
		rows = append(rows, Row{Name: strings.TrimSpace(get("name")), URL: strings.TrimSpace(get("url")),
			Username: strings.TrimSpace(get("username")), Password: get("password"), Note: strings.TrimSpace(get("note"))})
	}
}

// What happens to a row.
const (
	Add      = "add"      // a new secret
	Username = "username" // fills the username of an existing login that had none
	Skip     = "skip"     // already in the vault (or earlier in the file)
	Invalid  = "invalid"  // no password
)

// Line says what happens to one row. ID is the secret written (new or updated).
type Line struct {
	Action  string
	ID      string
	Name    string
	Site    string // host or Android package
	Differs bool   // added next to an existing login for the same site and username with another password
}

// Plan is the result of matching an export against a vault: the items to write and a line per row.
type Plan struct {
	Writes map[string]vault.Item
	Lines  []Line
}

// Count returns how many rows got an action.
func (p Plan) Count(action string) int {
	n := 0
	for _, l := range p.Lines {
		if l.Action == action {
			n++
		}
	}
	return n
}

// site is where a row's login is used: a web host or an Android package.
type site struct{ host, pkg string }

func (s site) String() string {
	if s.pkg != "" {
		return s.pkg
	}
	return s.host
}

func rowSite(r Row) site {
	if strings.HasPrefix(strings.ToLower(r.URL), "android://") {
		rest := r.URL[len("android://"):]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return site{pkg: strings.TrimRight(strings.SplitN(rest, "/", 2)[0], "/")}
	}
	if h := vault.Host(r.URL); h != "" {
		return site{host: h}
	}
	if looksLikeDomain(r.Name) {
		return site{host: vault.Host(r.Name)}
	}
	return site{}
}

// Build matches rows against the existing items (id -> item). newID makes ids for new items.
func Build(existing map[string]vault.Item, rows []Row, newID func() string, now time.Time) Plan {
	now = now.UTC().Truncate(time.Second)
	items := make(map[string]vault.Item, len(existing))
	for id, it := range existing {
		items[id] = it
	}
	plan := Plan{Writes: map[string]vault.Item{}}
	put := func(id string, it vault.Item) {
		items[id] = it
		plan.Writes[id] = it
	}

	for _, r := range rows {
		if r.Password == "" {
			plan.Lines = append(plan.Lines, Line{Action: Invalid, Name: r.Name})
			continue
		}
		s := rowSite(r)
		name := r.Name
		if name == "" {
			name = s.String()
		}
		line := Line{Name: name, Site: s.String()}

		// Logins already there for this site (or, without a site, with this name).
		var same, noUser, sameUser string
		for _, id := range sortedIDs(items) {
			it := items[id]
			if it.Kind != vault.KindSecret || it.Type != vault.TypePassword {
				continue
			}
			if s == (site{}) {
				if !strings.EqualFold(it.Name, name) || len(it.Contexts) > 0 {
					continue
				}
			} else if !usedAt(items, it, s) {
				continue
			}
			u, pw := it.Fields[vault.FieldUsername], it.Fields[vault.FieldPassword]
			switch {
			case u == r.Username && pw == r.Password:
				same = id
			case u == "" && pw == r.Password && r.Username != "" && noUser == "":
				noUser = id
			case u == r.Username && sameUser == "":
				sameUser = id
			}
		}
		switch {
		case same != "":
			line.Action, line.ID = Skip, same
		case noUser != "":
			it := items[noUser]
			fields := map[string]string{}
			for k, v := range it.Fields {
				fields[k] = v
			}
			fields[vault.FieldUsername] = r.Username
			it.Fields, it.UpdatedAt = fields, now
			put(noUser, it)
			line.Action, line.ID = Username, noUser
		default:
			secret := vault.Item{Kind: vault.KindSecret, Type: vault.TypePassword, Name: name,
				Fields: map[string]string{vault.FieldPassword: r.Password}, Notes: r.Note, CreatedAt: now, UpdatedAt: now}
			if r.Username != "" {
				secret.Fields[vault.FieldUsername] = r.Username
			}
			if s != (site{}) {
				ctxID := findContext(items, s)
				if ctxID == "" {
					ctxID = newID()
					ctx := vault.Item{Kind: vault.KindContext, Name: s.host, ContextType: vault.ContextWebsite,
						URLs: []string{origin(r.URL, s.host)}, CreatedAt: now, UpdatedAt: now}
					if s.pkg != "" {
						ctx = vault.Item{Kind: vault.KindContext, Name: name, ContextType: vault.ContextApp,
							AndroidPackages: []string{s.pkg}, CreatedAt: now, UpdatedAt: now}
					}
					put(ctxID, ctx)
				}
				secret.Contexts = []string{ctxID}
			}
			id := newID()
			put(id, secret)
			line.Action, line.ID, line.Differs = Add, id, sameUser != ""
		}
		plan.Lines = append(plan.Lines, line)
	}
	return plan
}

// usedAt reports whether a secret has a context for exactly this host or package.
func usedAt(items map[string]vault.Item, secret vault.Item, s site) bool {
	for _, cid := range secret.Contexts {
		if ctx, ok := items[cid]; ok && contextFor(ctx, s) {
			return true
		}
	}
	return false
}

func contextFor(ctx vault.Item, s site) bool {
	if ctx.Kind != vault.KindContext {
		return false
	}
	if s.pkg != "" {
		return slices.Contains(ctx.AndroidPackages, s.pkg)
	}
	for _, u := range ctx.URLs {
		if vault.Host(u) == s.host {
			return true
		}
	}
	return false
}

func findContext(items map[string]vault.Item, s site) string {
	for _, id := range sortedIDs(items) {
		if contextFor(items[id], s) {
			return id
		}
	}
	return ""
}

// origin keeps an http:// scheme (intranet devices) and drops the path; everything else becomes https://host.
func origin(raw, host string) string {
	if strings.HasPrefix(strings.ToLower(raw), "http://") {
		return "http://" + host
	}
	return "https://" + host
}

// sortedIDs makes matching deterministic: the same export always matches the same login.
func sortedIDs(items map[string]vault.Item) []string { return slices.Sorted(maps.Keys(items)) }

func looksLikeDomain(s string) bool {
	if strings.ContainsAny(s, " /@") || !strings.Contains(s, ".") {
		return false
	}
	tld := s[strings.LastIndex(s, ".")+1:]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}
