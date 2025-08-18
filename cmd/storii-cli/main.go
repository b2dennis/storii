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
	"strings"
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
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	var err error

	if os.Args[1] != "init" {
		_, err = loadConfig()
	}

	if os.Args[1] == "init" || err != nil {
		_, err = initConfig()
		if err != nil {
			fmt.Printf("Failed to initialize configuration: %v\n", err)
			return
		}
	}

	fmt.Println("Initialized successfully")
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

	fmt.Println("Do you have an account? y/n")
	scanner.Scan()
	hasAccountStr := scanner.Text()
	hasAccount := strings.ToLower(hasAccountStr) == "y"

	var username string
	var password string

	if hasAccount {
		fmt.Println("Logging in")
	} else {
		fmt.Println("Registering")
	}

	for {
		fmt.Printf("Username: ")
		scanner.Scan()
		username = scanner.Text()

		fmt.Printf("Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		if err != nil {
			fmt.Printf("Failed to read password\n")
			return Config{}, err
		}
		password = string(bytePassword)

		var token string
		if hasAccount {
			token, err = login(remote, username, password)
		} else {
			token, err = register(remote, username, password)
		}

		fmt.Println(token)

		if err != nil {
			fmt.Printf("Error occured: %v", err)
			return Config{}, err
		}

		if token != "" {
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

func login(remote, username, password string) (string, error) {
	requestData, _ := json.Marshal(models.LoginC2S{
		Username: username,
		Password: password,
	})

	req, err := http.NewRequest(http.MethodPost, remote+constants.RouteUser+constants.UserRouteLogin, bytes.NewReader(requestData))
	if err != nil {
		fmt.Println("Failed to login: Couldn't construct request")
		return "", errors.New("login_request_construction_failed")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to login: Request to remote failed")
		return "", errors.New("login_request_failed")
	}

	responseData, err := io.ReadAll(res.Body)
	var loginRes models.LoginS2C
	err = json.Unmarshal(responseData, &loginRes)

	// wrong password returns different type of response -> fails to unmarshal
	if err != nil {
		fmt.Println("Failed to login: Check your username and password")
		return "", nil
	}

	return loginRes.Token, nil
}

func register(remote, username, password string) (string, error) {
	requestData, _ := json.Marshal(models.CreateUserC2S{
		Username: username,
		Password: password,
	})

	req, err := http.NewRequest(http.MethodPost, remote+constants.RouteUser+constants.UserRouteRegister, bytes.NewReader(requestData))
	if err != nil {
		fmt.Println("Failed to register: Couldn't construct request")
		return "", errors.New("register_request_construction_failed")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to register: Request to remote failed")
		return "", errors.New("register_request_failed")
	}

	responseData, err := io.ReadAll(res.Body)
	var registerRes models.CreateUserS2C
	err = json.Unmarshal(responseData, &registerRes)

	// on error different struct is returned -> error
	if err != nil {
		fmt.Println("Failed to register: Username taken or password invalid")
		return "", nil
	}

	return login(remote, username, password)
}
