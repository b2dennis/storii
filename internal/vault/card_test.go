package vault

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCards(t *testing.T) {
	var v struct {
		Numbers []struct {
			Number, Brand, Masked string
			Valid                 bool
		}
		Expiry []struct{ Input, Normalized string }
	}
	b, err := os.ReadFile("../../testdata/cards.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Numbers {
		if got := CardBrand(c.Number); got != c.Brand {
			t.Errorf("CardBrand(%q) = %q, want %q", c.Number, got, c.Brand)
		}
		if got := CardValid(c.Number); got != c.Valid {
			t.Errorf("CardValid(%q) = %v", c.Number, got)
		}
		if got := CardMasked(c.Number); got != c.Masked {
			t.Errorf("CardMasked(%q) = %q", c.Number, got)
		}
	}
	for _, e := range v.Expiry {
		if got := NormalizeExpiry(e.Input); got != e.Normalized {
			t.Errorf("NormalizeExpiry(%q) = %q, want %q", e.Input, got, e.Normalized)
		}
	}
}
