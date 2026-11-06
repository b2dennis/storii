package vault

import (
	"net/url"
	"strings"
)

// Host normalizes a context URL or page URL to the host used for matching: lowercase, no port, no "www.".
// Bare domains ("github.com") are accepted. It returns "" for things that have no host.
func Host(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	return strings.TrimPrefix(h, "www.")
}

// MatchesHost reports whether a page on pageHost should be offered secrets of a context with contextURL:
// the same host, or a subdomain of it (a context for google.com also matches accounts.google.com).
func MatchesHost(contextURL, pageHost string) bool {
	ch := Host(contextURL)
	ph := Host(pageHost)
	if ch == "" || ph == "" {
		return false
	}
	return ph == ch || strings.HasSuffix(ph, "."+ch)
}

// MatchesContext reports whether a context applies to a web page host or an Android package name. Either may be
// empty.
func (it Item) MatchesContext(pageHost, androidPackage string) bool {
	if it.Kind != KindContext {
		return false
	}
	if pageHost != "" {
		for _, u := range it.URLs {
			if MatchesHost(u, pageHost) {
				return true
			}
		}
	}
	if androidPackage != "" {
		for _, p := range it.AndroidPackages {
			if p == androidPackage {
				return true
			}
		}
	}
	return false
}
