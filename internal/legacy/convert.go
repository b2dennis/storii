package legacy

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/vault"
)

// namespace for the deterministic ids of migrated items.
var namespace = uuid.MustParse("6f0e4a7c-2a0b-4c1d-9a55-5d3e1c0b7a11")

// Result of converting a v1 vault.
type Result struct {
	Items  map[string]vault.Item // id -> item, secrets and contexts
	Failed map[string]error      // v1 name -> why it couldn't be decrypted
}

// Convert decrypts v1 passwords and turns each into a password secret. Its associated URL (or a name that looks
// like a domain, which is how v1 entries were usually named) becomes a website context; entries for the same host
// share one. Ids depend only on the v1 username and entry name, so converting twice gives the same items.
func Convert(v1User string, pws []Password, masterPassword string, now time.Time) Result {
	res := Result{Items: map[string]vault.Item{}, Failed: map[string]error{}}
	now = now.UTC().Truncate(time.Second)
	for _, p := range pws {
		plain, err := p.Decrypt(masterPassword)
		if err != nil {
			res.Failed[p.Name] = err
			continue
		}
		secret := vault.Item{Kind: vault.KindSecret, Type: vault.TypePassword, Name: p.Name,
			Fields:    map[string]string{vault.FieldPassword: plain},
			Notes:     fmt.Sprintf("Imported from storii v1 (%s).", v1User),
			CreatedAt: now, UpdatedAt: now}
		site := p.AssociatedURL
		if site == "" && looksLikeDomain(p.Name) {
			site = p.Name
		}
		if host := vault.Host(site); host != "" {
			ctxID := uuid.NewSHA1(namespace, []byte("context:"+v1User+":"+host)).String()
			if _, ok := res.Items[ctxID]; !ok {
				u := site
				if !strings.Contains(u, "://") {
					u = "https://" + host
				}
				res.Items[ctxID] = vault.Item{Kind: vault.KindContext, ContextType: vault.ContextWebsite, Name: host,
					URLs: []string{u}, CreatedAt: now, UpdatedAt: now}
			}
			secret.Contexts = []string{ctxID}
		}
		res.Items[uuid.NewSHA1(namespace, []byte("secret:"+v1User+":"+p.Name)).String()] = secret
	}
	return res
}

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
