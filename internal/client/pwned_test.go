package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPwned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/5BAA6" || r.Header.Get("Add-Padding") != "true" {
			t.Errorf("request %s, padding %q", r.URL.Path, r.Header.Get("Add-Padding"))
		}
		w.Write([]byte("1E2AAA439972480CEC7F16C795BBB429372:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n"))
	}))
	defer srv.Close()
	old := PwnedURL
	PwnedURL = srv.URL + "/"
	defer func() { PwnedURL = old }()
	if n, err := Pwned(context.Background(), "password"); err != nil || n != 42 {
		t.Fatalf("Pwned = %d, %v", n, err)
	}
}
