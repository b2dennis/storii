package vault

import (
	"fmt"
	"strconv"
	"strings"
)

// Card fields (TypeCard).
const (
	FieldCardholder = "cardholder"
	FieldNumber     = "number"
	FieldExpiry     = "expiry" // MM/YY
	FieldCVC        = "cvc"
)

// CardDigits keeps only the digits of a card number ("4242 4242-…" → "42424242…").
func CardDigits(number string) string {
	var b strings.Builder
	for _, r := range number {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CardBrand guesses the network from the number's prefix: visa, mastercard, amex, discover, diners, jcb, unionpay,
// maestro, or "" when unknown. Shared cases: testdata/cards.json.
func CardBrand(number string) string {
	d := CardDigits(number)
	p := func(n int) int {
		if len(d) < n {
			return -1
		}
		v, _ := strconv.Atoi(d[:n])
		return v
	}
	switch {
	case p(2) == 34 || p(2) == 37:
		return "amex"
	case p(3) >= 300 && p(3) <= 305 || p(2) == 36 || p(2) == 38:
		return "diners"
	case p(4) >= 3528 && p(4) <= 3589:
		return "jcb"
	case p(1) == 4:
		return "visa"
	case p(2) >= 51 && p(2) <= 55 || p(4) >= 2221 && p(4) <= 2720:
		return "mastercard"
	case p(4) == 6011 || p(2) == 65 || p(3) >= 644 && p(3) <= 649:
		return "discover"
	case p(2) == 62:
		return "unionpay"
	case p(4) == 5018 || p(4) == 5020 || p(4) == 5038 || p(4) == 5893 || p(4) == 6304 || p(4) == 6759 ||
		p(4) >= 6761 && p(4) <= 6763 || p(4) == 604:
		return "maestro"
	}
	return ""
}

// CardValid checks the length (12–19 digits) and the Luhn checksum.
func CardValid(number string) bool {
	d := CardDigits(number)
	if len(d) < 12 || len(d) > 19 {
		return false
	}
	sum := 0
	for i := range len(d) {
		n := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// CardMasked is how lists show a card: "•••• 4242".
func CardMasked(number string) string {
	d := CardDigits(number)
	if len(d) > 4 {
		d = d[len(d)-4:]
	}
	return "•••• " + d
}

// NormalizeExpiry reads "12/29", "1/30", "12/2029" or "1229" as "MM/YY"; "" if it isn't a valid month.
func NormalizeExpiry(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	var m, y string
	if a, b, ok := strings.Cut(s, "/"); ok {
		m, y = a, b
	} else if len(s) == 4 || len(s) == 6 {
		m, y = s[:2], s[2:]
	}
	if len(y) == 4 {
		y = y[2:]
	}
	mi, err1 := strconv.Atoi(m)
	yi, err2 := strconv.Atoi(y)
	if err1 != nil || err2 != nil || len(y) != 2 || mi < 1 || mi > 12 || yi < 0 {
		return ""
	}
	return fmt.Sprintf("%02d/%02d", mi, yi)
}
