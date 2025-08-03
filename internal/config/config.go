package config

import (
	"io"
	"time"
)

type Config struct {
	Address   string
	DBPath    string
	JWTSecret string
	JWTExpiry time.Duration
	LogOutput io.Writer
}
