package vault

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestHealth(t *testing.T) {
	b, err := os.ReadFile("../../testdata/health.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Weak []struct {
			Password string
			Weak     bool
		}
		Items  map[string]Item
		Health Health
		Pwned  struct {
			Password, Prefix, Suffix, Body string
			Count                          int
			MissingSuffix                  string `json:"missing_suffix"`
			PaddingSuffix                  string `json:"padding_suffix"`
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Weak {
		if got := Weak(c.Password); got != c.Weak {
			t.Errorf("Weak(%q) = %v", c.Password, got)
		}
	}
	if got := CheckHealth(v.Items); !reflect.DeepEqual(got, v.Health) {
		t.Errorf("CheckHealth = %+v, want %+v", got, v.Health)
	}
	p := v.Pwned
	if pre, suf := PwnedHash(p.Password); pre != p.Prefix || suf != p.Suffix {
		t.Errorf("PwnedHash = %s %s", pre, suf)
	}
	if n := PwnedCount(p.Body, p.Suffix); n != p.Count {
		t.Errorf("PwnedCount = %d", n)
	}
	if PwnedCount(p.Body, p.MissingSuffix) != 0 || PwnedCount(p.Body, p.PaddingSuffix) != 0 {
		t.Error("missing or padding suffix counted")
	}
}
