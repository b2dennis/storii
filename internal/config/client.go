package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/b2dennis/storii/internal/constants"
)

// Struct holding necessary client information.
type ClientConfig struct {
	Remote    string `json:"api_address"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExitDelay int    `json:"exit_delay"`
}

// Helper function to load a ClientConfig from a file.
func LoadClientConfig(configFile string) (ClientConfig, error) {
	dat, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("No configuration found - Initializing\n")
		return ClientConfig{}, err
	}

	var conf ClientConfig
	err = json.Unmarshal(dat, &conf)
	if err != nil {
		fmt.Printf("Configuration invalid - Reinitializing\n")
		return ClientConfig{}, err
	}

	return conf, nil
}

// Validates the remote by checking the ping endpoint.
func IsRemoteValid(remote string) bool {
	req, err := http.NewRequest(http.MethodGet, remote+constants.RouteUtil+constants.UtilRoutePing, bytes.NewReader([]byte{}))
	if err != nil {
		fmt.Println("Failed to validate remote: Couldn't construct request")
		return false
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to validate remote: Request to remote failed")
		return false
	}

	body, err := io.ReadAll(res.Body)
	return string(body) == constants.PingRouteSuccessResponse
}
