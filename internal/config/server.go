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
	expiryHours, err := strconv.Atoi(getEnv(constants.VarJWTExpiry, constants.DefaultJWTExpiry))
	if err != nil {
		fmt.Printf("Value %s for env var %s is invalid! Must be an integer.", os.Getenv(constants.VarJWTExpiry), constants.VarJWTExpiry)
		expiryHours = 24
	}
	var logOutput io.Writer
	switch strings.ToLower(getEnv(constants.VarLogOutput, constants.DefaultLogOutput)) {
	case "stdout":
		logOutput = os.Stdout
	case "stderr":
		logOutput = os.Stderr
	default:
		logOutput = os.Stdout
		fmt.Printf("Value %s for env var %s is invalid! Must be either stderr or stdout.", os.Getenv(constants.VarLogOutput), constants.VarLogOutput)
	}

	return &ServerConfig{
		Address:   getEnv(constants.VarAddress, constants.DefaultAddress),
		JWTSecret: getEnv(constants.VarJWTSecret, constants.DefaultJWTSecret),
		JWTExpiry: time.Duration(expiryHours) * time.Hour,
		LogOutput: logOutput,
		DBHost:    getEnv(constants.VarDBHost, constants.DefaultDBHost),
		DBName:    getEnv(constants.VarDBName, constants.DefaultDBName),
		DBPort:    getEnv(constants.VarDBPort, constants.DefaultDBPort),
		DBUser:    getEnv(constants.VarDBUser, constants.DefaultDBUser),
		DBPass:    getEnv(constants.VarDBPass, constants.DefaultDBPass),
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
	DBHost    string
	DBName    string
	DBPort    string
	DBUser    string
	DBPass    string
	JWTSecret string
	JWTExpiry time.Duration
	LogOutput io.Writer
}
