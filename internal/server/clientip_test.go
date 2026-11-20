package server

import (
	"net/http/httptest"
	"testing"
	"unicode/utf8"
)

func TestClientIP(t *testing.T) {
	for _, c := range []struct {
		trust bool
		xff   []string
		want  string
	}{
		{false, []string{"1.1.1.1"}, "192.0.2.1"},
		{true, nil, "192.0.2.1"},
		{true, []string{"9.9.9.9"}, "9.9.9.9"},
		// A client can't pick its own rate limit bucket by sending a header the proxy appends to.
		{true, []string{"6.6.6.6, 9.9.9.9"}, "9.9.9.9"},
		{true, []string{"6.6.6.6", "9.9.9.9"}, "9.9.9.9"},
		{true, []string{" "}, "192.0.2.1"},
	} {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		s := &Server{cfg: Config{TrustProxy: c.trust}}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%v %q: got %s, want %s", c.trust, c.xff, got, c.want)
		}
	}
}

func TestDeviceName(t *testing.T) {
	long := ""
	for range 60 {
		long += "ä" // 2 bytes each
	}
	long = "x" + long
	got := deviceName(long)
	if len(got) > maxDeviceName || !utf8.ValidString(got) || got[:1] != "x" {
		t.Fatalf("%q (%d bytes)", got, len(got))
	}
	if deviceName("Pixel 9\xff") != "Pixel 9" {
		t.Fatal("kept invalid UTF-8")
	}
}
