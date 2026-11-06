package vault

import (
	"crypto/rand"
	"math/big"
	"strings"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*.()" // the set Google accepts, as in v1
)

// GeneratePassword returns a random password of length n (at least 4) with at least one of each character class
// that is enabled.
func GeneratePassword(n int, withSymbols bool) string {
	n = max(n, 4)
	classes := []string{lower, upper, digits}
	if withSymbols {
		classes = append(classes, symbols)
	}
	all := strings.Join(classes, "")
	for {
		out := make([]byte, n)
		for i := range out {
			out[i] = all[randInt(len(all))]
		}
		ok := true
		for _, c := range classes {
			ok = ok && strings.ContainsAny(string(out), c)
		}
		if ok {
			return string(out)
		}
	}
}

func randInt(n int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}
