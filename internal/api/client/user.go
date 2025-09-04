package client

import (
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
)

// Sends a request to register a new user.
func RegisterUser(conf models.ClientConfig) (models.CreateUserS2C, error) {
	data := models.CreateUserC2S{
		Username: conf.Username,
		Password: conf.MasterPassword,
	}
	return request[models.CreateUserS2C](conf, data, http.MethodPost, conf.Remote+constants.RouteUser+constants.UserRouteRegister)
}

// Sends a request to login an existing user.
func LoginUser(conf models.ClientConfig) (models.LoginS2C, error) {
	data := models.LoginC2S{
		Username: conf.Username,
		Password: conf.MasterPassword,
	}
	return request[models.LoginS2C](conf, data, http.MethodPost, conf.Remote+constants.RouteUser+constants.UserRouteLogin)
}

// Sends a request to delete an existing user.
func DeleteUser(conf models.ClientConfig) (models.DeleteUserS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.DeleteUserS2C{}, err
	}

	return request[models.DeleteUserS2C](conf, []byte{}, http.MethodDelete, conf.Remote+constants.RouteUser+constants.UserRouteDelete)
}

// Sends a request to update an existing user.
func UpdateUser(conf models.ClientConfig, data models.UpdateUserC2S) (models.UpdateUserS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.UpdateUserS2C{}, err
	}

	return request[models.UpdateUserS2C](conf, data, http.MethodPut, conf.Remote+constants.RouteUser+constants.UserRouteUpdate)
}
