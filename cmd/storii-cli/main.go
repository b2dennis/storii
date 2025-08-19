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

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"golang.org/x/term"
)

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
	var conf config.ClientConfig

	if os.Args[1] != "init" {
		conf, err = config.LoadClientConfig(configFile)
	}

	if os.Args[1] == "init" || err != nil {
		conf, err = initConfig()
		if err != nil {
			fmt.Printf("Failed to initialize configuration: %v\n", err)
			return
		}
	}

	jsonData, _ := json.Marshal(conf)
	file, err := os.Create(configFile)
	file.Write(jsonData)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("storii init")
	fmt.Println("storii set {name} {password}")
	fmt.Println("storii del {name}")
	fmt.Println("storii gen {name}")
}

func initConfig() (config.ClientConfig, error) {
	scanner := bufio.NewScanner(os.Stdin)
	var remote string

	for {
		fmt.Printf("Remote: ")
		scanner.Scan()
		remote = scanner.Text()

		if config.IsRemoteValid(remote) {
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
	var token string
	var err error

	if hasAccount {
		username, password, token, err = login(remote, scanner)
	} else {
		username, password, token, err = register(remote, scanner)
	}

	if err != nil {
		return config.ClientConfig{}, err
	}

	return config.ClientConfig{
		APIAddress: remote,
		Username:   username,
		Password:   password,
		Token:      token,
	}, nil
}

func login(remote string, scanner *bufio.Scanner) (string, string, string, error) {
	var username string
	var password string
	for {
		fmt.Print("Username: ")
		scanner.Scan()
		username = scanner.Text()

		fmt.Print("Password: ")
		passwordByte, err := term.ReadPassword(int(syscall.Stdin))
		password = string(passwordByte)
		fmt.Print("\n")

		responseData, err := client.LoginRequest(remote, username, password)
		var loginRes models.LoginS2C
		err = json.Unmarshal(responseData, &loginRes)

		// wrong password returns error response -> fails to unmarshal
		if err != nil {
			var errorRes models.ErrorS2C
			err = json.Unmarshal(responseData, &errorRes)
			fmt.Printf("Failed to login: %s, %s", errorRes.Message, errorRes.Error)
			continue
		}
		return username, password, loginRes.Token, nil
	}
}

func registerRequest(remote, username, password string) ([]byte, error) {
	requestData, _ := json.Marshal(models.CreateUserC2S{
		Username: username,
		Password: password,
	})

	req, err := http.NewRequest(http.MethodPost, remote+constants.RouteUser+constants.UserRouteRegister, bytes.NewReader(requestData))
	if err != nil {
		fmt.Println("Failed to register: Couldn't construct request")
		return []byte{}, errors.New("register_request_construction_failed")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to register: Request to remote failed")
		return []byte{}, errors.New("register_request_failed")
	}
	return io.ReadAll(res.Body)
}

func register(remote string, scanner *bufio.Scanner) (string, string, string, error) {
	var username string
	var password string
	for {
		fmt.Print("Username: ")
		scanner.Scan()
		username = scanner.Text()

		fmt.Print("Password: ")
		passwordByte, err := term.ReadPassword(int(syscall.Stdin))
		password = string(passwordByte)
		fmt.Print("\n")

		responseData, err := registerRequest(remote, username, password)
		var registerRes models.CreateUserS2C
		err = json.Unmarshal(responseData, &registerRes)

		// wrong password returns error response -> fails to unmarshal
		if err != nil {
			var errorRes models.ErrorS2C
			err = json.Unmarshal(responseData, &errorRes)
			fmt.Printf("Failed to register: %s, %s", errorRes.Message, errorRes.Error)
			continue
		}

		loginData, err := loginRequest(remote, username, password)
		var loginRes models.LoginS2C
		err = json.Unmarshal(responseData, &registerRes)

		if err != nil {
			var errorRes models.ErrorS2C
			err = json.Unmarshal(loginData, &errorRes)
			fmt.Printf("Failed to login: %s, %s", errorRes.Message, errorRes.Error)
			continue
		}

		return username, password, loginRes.Token, nil
	}
}
