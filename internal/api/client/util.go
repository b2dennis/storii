package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
)

func GeneratePassword(n int) string {
	permittedChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+*%&/()=?!$£{}:;.,-\\")
	retVal := make([]rune, n)
	for i := range n {
		retVal[i] = permittedChars[rand.Intn(len(permittedChars))]
	}

	return string(retVal)
}

func ReadResponse(data []byte, target any) error {
	var res models.SuccessS2C
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}

	resData, err := json.Marshal(res.Data)
	return json.Unmarshal(resData, target)
}

func request[K any](data any, config models.ClientConfig, method, url string) (K, error) {
	var res K

	requestData, err := json.Marshal(data)
	if err != nil {
		return res, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(requestData))
	if err != nil {
		return res, err
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, err
	}

	resData, err := io.ReadAll(response.Body)
	if err != nil {
		return res, err
	}

	err = ReadResponse(resData, &res)
	if err != nil {
		var errorRes models.ErrorS2C
		_ = json.Unmarshal(resData, &errorRes)
		return res, err
	}

	return res, nil

}

func checkAuth(conf models.ClientConfig) (models.ClientConfig, error) {
	if conf.Token == "" && (conf.Username == "" || conf.MasterPassword == "") {
		return models.ClientConfig{}, errors.New(constants.ErrorAuthRequired)
	}

	if conf.Token == "" {
		token, err := getToken(conf)
		if err != nil {
			return models.ClientConfig{}, errors.New(constants.ErrorAuthRequired)
		}

		conf.Token = token
	}

	return conf, nil
}

func getToken(conf models.ClientConfig) (string, error) {
	data := models.LoginC2S{
		Username: conf.Username,
		Password: conf.MasterPassword,
	}
	res, err := request[models.LoginS2C](data, http.MethodPost, conf.Remote+constants.RouteUser+constants.UserRouteLogin)
	if err != nil {
		return "", err
	}

	return res.Token, nil
}
