package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"golang.org/x/term"
)

type Config struct {
	APIAddress string `json:"api_address"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Token      string `json:"token"`
}

const configFile = "conf.json"

func main() {
	//  1. Check if config file exists -> conf.json
	//  N?
	//    1. Ask for remote (API Address)
	//    2. Validate remote (Ping endpoint)
	//    N? -> 1.
	//    3. Ask for username + password
	//    4. Validate (Login endpoint)
	//    N? -> 3.
	//    5. Save config
	//  2. Evaluate input
	//  storii register -> launch register script
	//  storii init -> launch init
	//  storii set {name} {password} -> store password with given name, print confirmation
	//  storii del {name} -> delete password with given name, print confirmation
	//  storii gen {name} -> store generated password with given name, print password
	if len(os.Args) < 1 {
		printUsage()
		return
	}

	var err error

	if os.Args[0] != "init" {
		_, err = loadConfig()
	}

	if os.Args[0] == "init" || err != nil {
		_, err = initConfig()
		if err != nil {
			fmt.Printf("Failed to initialize configuration: %v\n", err)
			return
		}
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("storii init")
	fmt.Println("storii set {name} {password}")
	fmt.Println("storii del {name}")
	fmt.Println("storii gen {name}")
}

func loadConfig() (Config, error) {
	dat, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("No configuration found - Initializing\n")
		return Config{}, err
	}

	var conf Config
	err = json.Unmarshal(dat, &conf)
	if err != nil {
		fmt.Printf("Configuration invalid - Reinitializing\n")
		return Config{}, err
	}

	return conf, nil
}

func initConfig() (Config, error) {
	scanner := bufio.NewScanner(os.Stdin)
	isRemoteValid := false
	var remote string

	for {
		fmt.Printf("Remote: ")
		scanner.Scan()
		remote = scanner.Text()

		isRemoteValid = checkRemoteValid(remote)
		if isRemoteValid {
			break
		}
		fmt.Printf("Remote %s is invalid\n", remote)
	}

	isLoggedIn := false
	var username string
	var password string

	for {
		fmt.Printf("Username: ")
		scanner.Scan()
		username = scanner.Text()

		fmt.Printf("Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("Failed to read password\n")
			return Config{}, err
		}
		password = string(bytePassword)

		token, err := login(remote, username, password)

		if err != nil {
			fmt.Printf("Error occured: %v", err)
			return Config{}, err
		}

		if token != "" {
			isLoggedIn = true
		}

		if isLoggedIn {
			break
		}
	}

	return Config{
		APIAddress: remote,
		Username:   username,
		Password:   password,
	}, nil
}

func checkRemoteValid(remote string) bool {
	req, err := http.NewRequest(http.MethodGet, remote+constants.RouteUtil+constants.UtilRoutePing, bytes.NewReader([]byte{}))
	if err != nil {
		fmt.Printf("Failed to validate remote: Couldn't construct request")
		return false
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Failed to validate remote: Request to remote failed")
		return false
	}

	body, err := io.ReadAll(res.Body)
	return string(body) == constants.PingRouteSuccessResponse
}

func login(remote, username, password string) (string, error) {
	requestData, _ := json.Marshal(models.LoginC2S{
		Username: username,
		Password: password,
	})

	req, err := http.NewRequest(http.MethodPost, remote+constants.RouteUser+constants.UserRouteLogin, bytes.NewReader(requestData))
	if err != nil {
		fmt.Printf("Failed to login: Couldn't construct request")
		return "", errors.New("login_request_construction_failed")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Failed to login: Request to remote failed")
		return "", errors.New("login_request_failed")
	}

	responseData, err := io.ReadAll(res.Body)
	var loginRes models.LoginS2C
	err = json.Unmarshal(responseData, &loginRes)

	// wrong password returns different type of response -> fails to unmarshal
	if err != nil {
		fmt.Printf("Failed to login: Check your username and password")
		return "", nil
	}

	return loginRes.Token, nil
}
