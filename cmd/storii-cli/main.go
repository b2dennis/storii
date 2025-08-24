package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/b2dennis/storii/internal/api/client"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/crypto"
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
	clientConfig := models.ClientConfig{
		Remote:         conf.Remote,
		Username:       conf.Username,
		MasterPassword: conf.Password,
	}

	switch strings.ToLower(os.Args[1]) {
	case "set":
		encrypted := crypto.EncryptPassword([]byte(os.Args[3]), []byte(conf.Password))
		data := models.SetPasswordC2S{
			Name:    os.Args[2],
			Value:   string(encrypted.Value),
			IV:      string(encrypted.IV),
			AuthTag: string(encrypted.AuthTag),
			Salt:    string(encrypted.Salt),
		}

		res, err := client.SetPassword(clientConfig, data)
		if err != nil {
			fmt.Printf("Failed to set password: %v\n", err)
			return
		}
		fmt.Printf("Successfully set password \"%s\".\n", res.NewPassword.Name)
	case "del":
		data := models.DeletePasswordC2S{
			Name: os.Args[2],
		}
		res, err := client.DeletePassword(clientConfig, data)
		if err != nil {
			fmt.Printf("Failed to delete password: %v\n", err)
			return
		}
		fmt.Printf("Successfully deleted password \"%s\".\n", res.Name)
	case "gen":
		password := client.GeneratePassword(24)

		encrypted := crypto.EncryptPassword([]byte(password), []byte(conf.Password))
		data := models.SetPasswordC2S{
			Name:    os.Args[2],
			Value:   string(encrypted.Value),
			IV:      string(encrypted.IV),
			AuthTag: string(encrypted.AuthTag),
			Salt:    string(encrypted.Salt),
		}

		res, err := client.SetPassword(clientConfig, data)
		if err != nil {
			fmt.Printf("Failed to set password: %v\n", err)
			return
		}
		fmt.Printf("Successfully set password \"%s\" to \"%s\".\n", res.NewPassword.Name, password)
	case "get":
		res, err := client.ListPasswords(clientConfig)
		if err != nil {
			fmt.Printf("Failed to get passwords: %v\n", err)
			return
		}
		for _, password := range res.Passwords {
			if password.Name == os.Args[2] {
				decrypted, err := crypto.DecryptPassword(password.Value, password.IV, password.AuthTag, password.Salt, conf.Password)
				if err != nil {
					fmt.Println("Couldn't decrypt password")
					return
				}
				fmt.Println(decrypted)
				return
			}
		}
		fmt.Printf("Password \"%s\" was not found.", os.Args[2])
	case "lst":
		res, err := client.ListPasswords(clientConfig)
		if err != nil {
			fmt.Printf("Failed to get passwords: %v\n", err)
			return
		}
		for i, password := range res.Passwords {
			fmt.Printf("%d: %s\n", i, password.Name)
		}
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("storii init")
	fmt.Println("storii lst")
	fmt.Println("storii get <name>")
	fmt.Println("storii del <name>")
	fmt.Println("storii gen <name>")
	fmt.Println("storii set <name> <password>")
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

		conf := models.ClientConfig{
			Remote:         remote,
			Username:       username,
			MasterPassword: password,
		}

		_, err = client.LoginUser(conf)
		if err != nil {
			fmt.Println("Username or Password invalid, please retry.")
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

		conf := models.ClientConfig{
			Remote:         remote,
			Username:       username,
			MasterPassword: password,
		}

		_, err = client.RegisterUser(conf)
		if err != nil {
			fmt.Println("Username or Password invalid, please retry.")
			continue
		}

		_, err = client.LoginUser(conf)

		if err != nil {
			fmt.Println("Username or Password invalid, please retry.")
			continue
		}

		return username, password, nil
	}
}
