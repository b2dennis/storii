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

func LoginRequest(remote, username, password string) ([]byte, error) {
	requestData, _ := json.Marshal(models.LoginC2S{
		Username: username,
		Password: password,
	})

	req, err := http.NewRequest(http.MethodPost, remote+constants.RouteUser+constants.UserRouteLogin, bytes.NewReader(requestData))
	if err != nil {
		fmt.Println("Failed to login: Couldn't construct request")
		return []byte{}, errors.New("login_request_construction_failed")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to login: Request to remote failed")
		return []byte{}, errors.New("login_request_failed")
	}
	return io.ReadAll(res.Body)
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

// TODO: Login
func SetPasswordRequest(remote, name, secret, masterPassword string) bool {
	encrypted := crypto.EncryptPassword([]byte(secret), []byte(masterPassword))
	data := models.AddPasswordC2S{
		Name:          name,
		Value:         string(encrypted.Value),
		IV:            string(encrypted.IV),
		AuthTag:       string(encrypted.AuthTag),
		Salt:          string(encrypted.Salt),
		AssociatedURL: "",
	}

	dataJson, _ := json.Marshal(data)

	req, err := http.NewRequest(http.MethodPut, remote+constants.RoutePassword+constants.PasswordRouteUpdate, bytes.NewReader(dataJson))
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
	var resStruct models.AddPasswordS2C

	json.Unmarshal(dataBytes, &resStruct)
	if err != nil {
		var resError models.ErrorS2C
		json.Unmarshal(dataBytes, &resError)
		fmt.Printf("Failed to update password: %s, %s\n", resError.Message, resError.Error)
		return false
	}
	return true
}
func DeletePasswordRequest(name string)
func GeneratePasswordRequest(name string)
func GetPasswordRequest(name string)
func ListPasswordsRequest()
