package vault

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// WeakBits is the estimated strength below which a password counts as weak.
const WeakBits = 50

// Weak reports whether a password is too short or too guessable: fewer than 8 characters, fewer than 5 different
// characters, or under WeakBits by length × log2(character pool), where the pool counts 26 for lowercase letters, 26 for
// uppercase, 10 for digits and 33 for anything else that appears. Shared cases: testdata/health.json.
func Weak(pw string) bool {
	r := []rune(pw)
	if len(r) < 8 {
		return true
	}
	uniq := map[rune]bool{}
	var lower, upper, digit, other bool
	for _, c := range r {
		uniq[c] = true
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			other = true
		}
	}
	if len(uniq) < 5 {
		return true
	}
	pool := 0
	for _, p := range []struct {
		on bool
		n  int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {other, 33}} {
		if p.on {
			pool += p.n
		}
	}
	return float64(len(r))*math.Log2(float64(pool)) < WeakBits
}

// Health lists the password items that need attention, by id: Weak ones and groups that share one password (Reused,
// each group sorted, groups sorted by their first id).
type Health struct {
	Weak   []string   `json:"weak"`
	Reused [][]string `json:"reused"`
}

// CheckHealth looks at every password item with a password.
func CheckHealth(items map[string]Item) Health {
	h := Health{Weak: []string{}, Reused: [][]string{}}
	by := map[string][]string{}
	for id, it := range items {
		pw := it.Fields[FieldPassword]
		if it.Kind != KindSecret || it.Type != TypePassword || pw == "" {
			continue
		}
		if Weak(pw) {
			h.Weak = append(h.Weak, id)
		}
		by[pw] = append(by[pw], id)
	}
	for _, ids := range by {
		if len(ids) > 1 {
			slices.Sort(ids)
			h.Reused = append(h.Reused, ids)
		}
	}
	slices.Sort(h.Weak)
	slices.SortFunc(h.Reused, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
	return h
}

// PwnedRangeURL is Have I Been Pwned's k-anonymity API: only the first 5 hex digits of the SHA-1 leave the device.
// Send "Add-Padding: true" so the response size gives nothing away.
const PwnedRangeURL = "https://api.pwnedpasswords.com/range/"

// PwnedHash splits a password's uppercase SHA-1 into the prefix sent to PwnedRangeURL and the suffix looked up in the
// answer.
func PwnedHash(pw string) (prefix, suffix string) {
	s := sha1.Sum([]byte(pw))
	h := strings.ToUpper(hex.EncodeToString(s[:]))
	return h[:5], h[5:]
}

// PwnedCount reads a range answer ("SUFFIX:COUNT" lines; padding lines have count 0) and returns how often suffix was
// seen in breaches.
func PwnedCount(body, suffix string) int {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		s, n, ok := strings.Cut(strings.TrimFunc(sc.Text(), unicode.IsSpace), ":")
		if ok && strings.EqualFold(s, suffix) {
			c, _ := strconv.Atoi(n)
			return c
		}
	}
	return 0
}
