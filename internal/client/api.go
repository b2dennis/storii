package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
)

func ClientLoginRequest(remote, username, password string) ([]byte, error) {
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
