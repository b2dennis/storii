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
		fmt.Println("Failed to update password: Couldn't construct request")
		return false
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to update password: Request to remote failed")
		return false
	}

	dataBytes, err := io.ReadAll(res.Body)
	var resStruct models.SetPasswordS2C

	json.Unmarshal(dataBytes, &resStruct)
	if err != nil {
		var resError models.ErrorS2C
		json.Unmarshal(dataBytes, &resError)
		fmt.Printf("Failed to update password: %s, %s\n", resError.Message, resError.Error)
		return false
	}
	return true
}
func DeletePasswordRequest(name string) {

}
func GeneratePasswordRequest(name string) {

}
func GetPasswordRequest(name string) {

}
func ListPasswordsRequest() {

}
