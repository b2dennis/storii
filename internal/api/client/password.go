package client

import (
	"errors"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
)

func SetPassword(conf models.ClientConfig, data models.SetPasswordC2S) (models.SetPasswordS2C, error) {
	if conf.Token == "" && (conf.Username == "" || conf.MasterPassword == "") {
		return models.SetPasswordS2C{}, errors.New(constants.ErrorTokenRequired)
	}

}
