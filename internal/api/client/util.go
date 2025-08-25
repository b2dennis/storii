package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"reflect"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
)

func GeneratePassword(n int) string {
	permittedChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*.()")
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

func request[K any](conf models.ClientConfig, data any, method, url string) (K, error) {
	var res K
	var none K

	requestData, err := json.Marshal(data)
	if err != nil {
		return none, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(requestData))
	if err != nil {
		return none, err
	}

	if conf.Token != "" {
		req.Header.Add("Authorization", "Bearer "+conf.Token)
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return none, err
	}
	defer response.Body.Close()

	resData, err := io.ReadAll(response.Body)
	if err != nil {
		return none, err
	}

	err = ReadResponse(resData, &res)
	if err != nil {
		return none, err
	}

	if reflect.DeepEqual(res, none) {
		var errorRes models.ErrorS2C
		err = json.Unmarshal(resData, &errorRes)
		if err != nil {
			return none, err
		}
		return none, errors.New(errorRes.Error)
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
	res, err := LoginUser(conf)
	if err != nil {
		return "", err
	}

	return res.Token, nil
}
