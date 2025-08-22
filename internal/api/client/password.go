package client

import (
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
)

func SetPassword(conf models.ClientConfig, data models.SetPasswordC2S) (models.SetPasswordS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.SetPasswordS2C{}, err
	}

	return request[models.SetPasswordS2C](conf, data, http.MethodPost, conf.Remote+constants.RoutePassword+constants.PasswordRouteSet)
}

func DeletePassword(conf models.ClientConfig, data models.DeletePasswordC2S) (models.DeletePasswordS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.DeletePasswordS2C{}, err
	}

	return request[models.DeletePasswordS2C](conf, data, http.MethodDelete, conf.Remote+constants.RoutePassword+constants.PasswordRouteDelete)
}

func ListPasswords(conf models.ClientConfig) (models.ListPasswordsS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.ListPasswordsS2C{}, err
	}

	return request[models.ListPasswordsS2C](conf, []byte{}, http.MethodGet, conf.Remote+constants.RoutePassword+constants.PasswordRouteList)
}

func UpdatePassword(conf models.ClientConfig, data models.UpdatePasswordC2S) (models.UpdatePasswordS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.UpdatePasswordS2C{}, err
	}

	return request[models.UpdatePasswordS2C](conf, data, http.MethodPut, conf.Remote+constants.RoutePassword+constants.PasswordRouteUpdate)
}
