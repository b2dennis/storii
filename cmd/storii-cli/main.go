package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/config"
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
	//  storii get {name} -> get password from name
	//  storii lst -> list all passwords
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
		jsonData, _ := json.Marshal(conf)
		file, err := os.Create(configFile)
		if err != nil {
			fmt.Printf("Failed to create config file: %v\n", err)
			return
		}
		file.Write(jsonData)
		return
	}
	switch strings.ToLower(os.Args[1]) {
	case "set":
		client.SetPasswordRequest(conf.Remote, conf.Username, conf.Password, os.Args[2], os.Args[3])
	case "del":
		client.DeletePasswordRequest(os.Args[2])
	case "gen":
		client.GeneratePasswordRequest(os.Args[2])
	case "get":
		client.GetPasswordRequest(conf.Remote, conf.Username, conf.Password, os.Args[2])
	case "lst":
		client.ListPasswordsRequest(conf.Remote, conf.Username, conf.Password)
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("storii init")
	fmt.Println("storii lst")
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
	var err error

	if hasAccount {
		username, password, err = login(remote, scanner)
	} else {
		username, password, err = register(remote, scanner)
	}

	if err != nil {
		return config.ClientConfig{}, err
	}

	return config.ClientConfig{
		Remote:   remote,
		Username: username,
		Password: password,
	}, nil
}

func login(remote string, scanner *bufio.Scanner) (string, string, error) {
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
		err = client.ReadResponse(responseData, &loginRes)

		// wrong password returns error response -> fails to unmarshal
		if err != nil {
			var errorRes models.ErrorS2C
			err = json.Unmarshal(responseData, &errorRes)
			fmt.Printf("Failed to login: %s, %s", errorRes.Message, errorRes.Error)
			continue
		}
		return username, password, nil
	}
}

func register(remote string, scanner *bufio.Scanner) (string, string, error) {
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

		responseData, err := client.RegisterRequest(remote, username, password)
		var registerRes models.CreateUserS2C
		err = json.Unmarshal(responseData, &registerRes)

		// wrong password returns error response -> fails to unmarshal
		if err != nil {
			var errorRes models.ErrorS2C
			err = json.Unmarshal(responseData, &errorRes)
			fmt.Printf("Failed to register: %s, %s", errorRes.Message, errorRes.Error)
			continue
		}

		loginData, err := client.LoginRequest(remote, username, password)
		err = json.Unmarshal(responseData, &registerRes)

		if err != nil {
			var errorRes models.ErrorS2C
			err = json.Unmarshal(loginData, &errorRes)
			fmt.Printf("Failed to login: %s, %s", errorRes.Message, errorRes.Error)
			continue
		}

		return username, password, nil
	}
}
