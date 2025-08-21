package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/crypto"
	"github.com/b2dennis/storii/internal/models"
)

func ReadResponse(data []byte, target any) error {
	var res models.SuccessS2C
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	resData, err := json.Marshal(res.Data)
	err = json.Unmarshal(resData, target)
	return err
}

func LoginRequest(remote, username, password string) ([]byte, error) {
	requestData, err := json.Marshal(models.LoginC2S{
		Username: username,
		Password: password,
	})
	if err != nil {
		fmt.Printf("Failed to login: %v", err)
		return []byte{}, err
	}

	req, err := http.NewRequest(http.MethodPost, remote+constants.RouteUser+constants.UserRouteLogin, bytes.NewReader(requestData))
	if err != nil {
		fmt.Println("Failed to login: Couldn't construct request")
		return []byte{}, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to login: Request to remote failed")
		return []byte{}, err
	}
	return io.ReadAll(res.Body)
}

func getToken(remote, username, password string) (string, error) {
	resData, err := LoginRequest(remote, username, password)
	if err != nil {
		return "", err
	}

	var loginRes models.LoginS2C
	err = ReadResponse(resData, &loginRes)
	if err != nil {
		var errorRes models.ErrorS2C
		_ = json.Unmarshal(resData, &errorRes)
		fmt.Printf("Failed to login: %s, %s", errorRes.Message, errorRes.Error)
		return "", err
	}

	return loginRes.Token, nil
}

func RegisterRequest(remote, username, password string) ([]byte, error) {
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

func SetPasswordRequest(remote, username, masterPassword, name, secret string) bool {
	token, err := getToken(remote, username, masterPassword)
	if err != nil {
		fmt.Println("Failed to set password: Username, Password or Remote invalid, please use storii init again.")
	}
	encrypted := crypto.EncryptPassword([]byte(secret), []byte(masterPassword))

	data := models.SetPasswordC2S{
		Name:          name,
		Value:         string(encrypted.Value),
		IV:            string(encrypted.IV),
		AuthTag:       string(encrypted.AuthTag),
		Salt:          string(encrypted.Salt),
		AssociatedURL: "",
	}

	dataJson, _ := json.Marshal(data)

	req, err := http.NewRequest(http.MethodPost, remote+constants.RoutePassword+constants.PasswordRouteAdd, bytes.NewReader(dataJson))
	req.Header.Add("Authorization", "Bearer "+token)
	if err != nil {
		fmt.Println("Failed to set password: Couldn't construct request")
		return false
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to set password: Request to remote failed")
		return false
	}

	dataBytes, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Failed to set password: Couldn't read response")
	}
	var resStruct models.SetPasswordS2C

	err = ReadResponse(dataBytes, &resStruct)
	if err != nil {
		var resError models.ErrorS2C
		json.Unmarshal(dataBytes, &resError)
		fmt.Printf("Failed to set password: %s, %s\n", resError.Message, resError.Error)
		return false
	}
	fmt.Println("Password was successfuly set.")
	return true
}
func DeletePasswordRequest(name string) {

}
func GeneratePasswordRequest(name string) {

}
func GetPasswordRequest(remote, username, masterPassword, name string) bool {
	dataBytes, err := fetchPasswordRequest(remote, username, masterPassword)
	if err != nil {
		return false
	}
	var resStruct models.ListPasswordsS2C

	err = ReadResponse(dataBytes, &resStruct)
	if err != nil {
		var resError models.ErrorS2C
		json.Unmarshal(dataBytes, &resError)
		fmt.Printf("Failed to set password: %s, %s\n", resError.Message, resError.Error)
		return false
	}
	var target models.S2CPassword
	for _, password := range resStruct.Passwords {
		if password.Name == name {
			target = password
		}
	}

	decrypted, err := crypto.DecryptPassword(target.Value, target.IV, target.AuthTag, target.Salt, masterPassword)
	if err != nil {
		fmt.Println("Failed to decrypt password")
		return false
	}
	fmt.Println(decrypted)
	return true
}
func ListPasswordsRequest(remote, username, masterPassword string) bool {
	dataBytes, err := fetchPasswordRequest(remote, username, masterPassword)
	if err != nil {
		return false
	}
	var resStruct models.ListPasswordsS2C

	err = ReadResponse(dataBytes, &resStruct)
	if err != nil {
		var resError models.ErrorS2C
		json.Unmarshal(dataBytes, &resError)
		fmt.Printf("Failed to set password: %s, %s\n", resError.Message, resError.Error)
		return false
	}
	for _, password := range resStruct.Passwords {
		fmt.Println(password.Name)
	}
	return true
}

func fetchPasswordRequest(remote, username, masterPassword string) ([]byte, error) {
	token, err := getToken(remote, username, masterPassword)
	if err != nil {
		fmt.Println("Failed to fetch passwords: Username, Password or Remote invalid, please use storii init again.")
		return []byte{}, err
	}

	req, err := http.NewRequest(http.MethodGet, remote+constants.RoutePassword+constants.PasswordRouteList, bytes.NewReader([]byte{}))
	req.Header.Add("Authorization", "Bearer "+token)
	if err != nil {
		fmt.Println("Failed to fetch passwords: Couldn't construct request")
		return []byte{}, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to fetch passwords: Request to remote failed")
		return []byte{}, err
	}

	return io.ReadAll(res.Body)
}
