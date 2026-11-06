// Package config reads the server's environment. The v1 variable names still work.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	Address      string
	DatabaseURL  string
	Secret       []byte
	SessionTTL   time.Duration
	Registration bool
	TrustProxy   bool
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() (Server, error) {
	c := Server{Address: env("ADDRESS", ":9999"), TrustProxy: env("TRUSTPROXY", "false") == "true"}
	c.DatabaseURL = os.Getenv("DATABASE_URL")
	if c.DatabaseURL == "" {
		u := url.URL{Scheme: "postgres", Host: env("DBHOST", "localhost") + ":" + env("DBPORT", "5432"),
			Path: "/" + env("DBNAME", "postgres"), User: url.UserPassword(env("DBUSER", "default_user"), env("DBPASS", "default_pass")),
			RawQuery: "sslmode=" + env("DBSSLMODE", "disable")}
		c.DatabaseURL = u.String()
	}
	secret := env("SERVERSECRET", os.Getenv("JWTSECRET"))
	if len(secret) < 16 || secret == "b2dennis" {
		return c, fmt.Errorf("set SERVERSECRET (or JWTSECRET) to a random string of at least 16 characters")
	}
	c.Secret = []byte(secret)
	days, err := strconv.Atoi(env("SESSIONDAYS", "90"))
	if err != nil || days < 1 {
		return c, fmt.Errorf("SESSIONDAYS must be a positive number of days")
	}
	c.SessionTTL = time.Duration(days) * 24 * time.Hour
	switch strings.ToLower(env("REGISTRATION", "open")) {
	case "open":
		c.Registration = true
	case "closed":
	default:
		return c, fmt.Errorf("REGISTRATION must be open or closed")
	}
	return c, nil
}
