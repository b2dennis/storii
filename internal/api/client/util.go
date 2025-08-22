package client

import (
	"bytes"
	"encoding/json"
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

func request[K any](requestData any, method, route string) (K, error) {
}

func getToken(conf models.ClientConfig) (string, error) {
	requestData, err := json.Marshal(models.LoginC2S{
		Username: conf.Username,
		Password: conf.MasterPassword,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, conf.Remote+constants.RouteUser+constants.UserRouteLogin, bytes.NewReader(requestData))
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	resData, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var loginRes models.LoginS2C
	err = ReadResponse(resData, &loginRes)
	if err != nil {
		var errorRes models.ErrorS2C
		_ = json.Unmarshal(resData, &errorRes)
		return "", err
	}

	return loginRes.Token, nil
}
