package config

import (
	"fmt"
	"github.com/b2dennis/storii/internal/constants"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func LoadServerConfig() *ServerConfig {
	expiryHours, err := strconv.Atoi(getEnv(constants.VarJWTExpiry, "24"))
	if err != nil {
		fmt.Printf("Value %s for env var %s is invalid! Must be an integer.", os.Getenv(constants.VarJWTExpiry), constants.VarJWTExpiry)
		expiryHours = 24
	}
	var logOutput io.Writer
	switch strings.ToLower(getEnv(constants.VarLogOutput, "stdout")) {
	case "stdout":
		logOutput = os.Stdout
	case "stderr":
		logOutput = os.Stderr
	default:
		logOutput = os.Stdout
		fmt.Printf("Value %s for env var %s is invalid! Must be either stderr or stdout.", os.Getenv(constants.VarLogOutput), constants.VarLogOutput)
	}

	return &ServerConfig{
		Address:   getEnv(constants.VarAddress, ":9999"),
		DBPath:    getEnv(constants.VarDBPath, "data.db"),
		JWTSecret: getEnv(constants.VarJWTSecret, "b2dennis"),
		JWTExpiry: time.Duration(expiryHours) * time.Hour,
		LogOutput: logOutput,
	}
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value != "" {
		return value
	}
	return defaultValue
}

type ServerConfig struct {
	Address   string
	DBPath    string
	JWTSecret string
	JWTExpiry time.Duration
	LogOutput io.Writer
}
