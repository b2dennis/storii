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
