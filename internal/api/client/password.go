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

	res, err := request[models.SetPasswordS2C](data, conf, http.MethodPost, conf.Remote+constants.RoutePassword+constants.PasswordRouteSet)
	if err != nil {
		return models.SetPasswordS2C{}, err
	}

	return res, nil
}

func DeletePassword(conf models.ClientConfig, data models.DeletePasswordC2S) (models.DeletePasswordS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.DeletePasswordS2C{}, err
	}

	res, err := request[models.DeletePasswordS2C](data, conf, http.MethodPost, conf.Remote+constants.RoutePassword+constants.PasswordRouteDelete)
	if err != nil {
		return models.DeletePasswordS2C{}, err
	}

	return res, nil
}

func ListPasswords(conf models.ClientConfig) (models.ListPasswordsS2C, error) {
	conf, err := checkAuth(conf)
	if err != nil {
		return models.ListPasswordsS2C{}, err
	}

	res, err := request[models.ListPasswordsS2C]([]byte{}, conf, http.MethodGet, conf.Remote+constants.RoutePassword+constants.PasswordRouteList)
	if err != nil {
		return models.ListPasswordsS2C{}, err
	}

	return res, nil
}
