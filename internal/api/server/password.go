package handlers

import (
	"encoding/hex"
	"encoding/json"
	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/db"
	"github.com/b2dennis/storii/internal/middleware"
	"github.com/b2dennis/storii/internal/models"
	"github.com/b2dennis/storii/internal/utils"
	"github.com/b2dennis/storii/internal/validation"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

type PasswordHandlerManager struct {
	jwt            *middleware.JWT
	logger         *slog.Logger
	responseWriter *utils.ResponseWriter
	validator      *validation.Validator
	dbm            *db.DbManager
}

func NewPasswordHandlerManager(jwt *middleware.JWT, logger *slog.Logger, responseWriter *utils.ResponseWriter, validator *validation.Validator, dbm *db.DbManager) *PasswordHandlerManager {
	return &PasswordHandlerManager{
		jwt:            jwt,
		logger:         logger,
		responseWriter: responseWriter,
		validator:      validator,
		dbm:            dbm,
	}
}

func (phm *PasswordHandlerManager) RegisterPasswordHandlers(r *mux.Router) {
	var passwordHandlers []models.RequestHandlerStruct = []models.RequestHandlerStruct{
		{
			Handler: phm.jwt.JwtMiddleware(phm.GetPasswords),
			Method:  http.MethodGet,
			Route:   constants.PasswordRouteList,
		},
		{
			Handler: phm.jwt.JwtMiddleware(phm.SetPassword),
			Method:  http.MethodPost,
			Route:   constants.PasswordRouteSet,
		},
		{
			Handler: phm.jwt.JwtMiddleware(phm.DeletePassword),
			Method:  http.MethodDelete,
			Route:   constants.PasswordRouteDelete,
		},
		{
			Handler: phm.jwt.JwtMiddleware(phm.UpdatePassword),
			Method:  http.MethodPut,
			Route:   constants.PasswordRouteUpdate,
		},
	}
	subRouter := r.PathPrefix(constants.RoutePassword).Subrouter()
	for _, handler := range passwordHandlers {
		phm.logger.Info(constants.MessageRouteRegistered, constants.LogKeyRoute, constants.RoutePassword, constants.LogKeySubroute, handler.Route, constants.LogKeyMethod, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

func (phm *PasswordHandlerManager) GetPasswords(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var storedPasswords []models.StoredPassword
	phm.dbm.Db.Where("user_id = ?", uint(UserID)).Find(&storedPasswords)

	responsePasswords := make([]models.S2CPassword, len(storedPasswords))

	for i, storedPassword := range storedPasswords {
		responsePasswords[i] = models.S2CPassword{
			Name:          storedPassword.Name,
			Value:         hex.EncodeToString(storedPassword.Value),
			IV:            hex.EncodeToString(storedPassword.IV),
			AuthTag:       hex.EncodeToString(storedPassword.AuthTag),
			Salt:          hex.EncodeToString(storedPassword.Salt),
			AssociatedURL: storedPassword.AssociatedURL,
		}
	}

	response := models.ListPasswordsS2C{
		Passwords: responsePasswords,
	}

	phm.logger.InfoContext(r.Context(), constants.MessagePasswordsFetched)
	phm.responseWriter.WriteSuccessResponse(r.Context(), w, response, http.StatusOK)
}

func (phm *PasswordHandlerManager) SetPassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var setPasswordRequest models.SetPasswordC2S
	err = json.NewDecoder(r.Body).Decode(&setPasswordRequest)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := phm.validator.ValidateStruct(setPasswordRequest)
	if len(validationErrors) > 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	value, err := hex.DecodeString(setPasswordRequest.Value)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password value to byte array")
		return
	}

	iv, err := hex.DecodeString(setPasswordRequest.IV)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password IV to byte array")
		return
	}

	authTag, err := hex.DecodeString(setPasswordRequest.AuthTag)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password auth tag to byte array")
		return
	}

	salt, err := hex.DecodeString(setPasswordRequest.Salt)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform keygen salt to byte array")
		return
	}

	newPassword := &models.StoredPassword{
		UserID:        uint(UserID),
		Name:          setPasswordRequest.Name,
		Value:         value,
		IV:            iv,
		AuthTag:       authTag,
		Salt:          salt,
		AssociatedURL: setPasswordRequest.AssociatedURL,
	}

	result := phm.dbm.Db.Create(newPassword)
	if result.RowsAffected == 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorCreationFailed, "Could not create password")
		return
	}

	response := models.SetPasswordS2C{
		NewPassword: models.S2CPassword{
			Name:          newPassword.Name,
			Value:         hex.EncodeToString(newPassword.Value),
			IV:            hex.EncodeToString(newPassword.IV),
			AuthTag:       hex.EncodeToString(newPassword.AuthTag),
			Salt:          hex.EncodeToString(newPassword.Salt),
			AssociatedURL: newPassword.AssociatedURL,
		},
	}

	phm.logger.InfoContext(r.Context(), constants.MessagePasswordSet, constants.LogKeyPasswordName, newPassword.Name)
	phm.responseWriter.WriteSuccessResponse(r.Context(), w, response, http.StatusCreated)
}

func (phm *PasswordHandlerManager) DeletePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var deletePasswordRequest models.DeletePasswordC2S
	err = json.NewDecoder(r.Body).Decode(&deletePasswordRequest)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := phm.validator.ValidateStruct(deletePasswordRequest)
	if len(validationErrors) > 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingPassword models.StoredPassword
	result := phm.dbm.Db.Where("user_id = ? AND name = ?", UserID, deletePasswordRequest.Name).First(&existingPassword)
	if result.RowsAffected == 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	result = phm.dbm.Db.Delete(&existingPassword)
	if result.RowsAffected == 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Failed to delete password")
		return
	}

	response := models.DeletePasswordS2C{
		Name: existingPassword.Name,
	}

	phm.logger.InfoContext(r.Context(), constants.MessagePasswordDeleted, constants.LogKeyPasswordName, existingPassword.Name)
	phm.responseWriter.WriteSuccessResponse(r.Context(), w, response)
}

func (phm *PasswordHandlerManager) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	UserIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(UserIDStr, 10, 64)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updatePasswordRequest models.UpdatePasswordC2S
	err = json.NewDecoder(r.Body).Decode(&updatePasswordRequest)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := phm.validator.ValidateStruct(updatePasswordRequest)
	if len(validationErrors) > 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingPassword models.StoredPassword
	result := phm.dbm.Db.Where("user_id = ? AND name = ?", UserID, updatePasswordRequest.Name).First(&existingPassword)
	if result.RowsAffected == 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	value, err := hex.DecodeString(updatePasswordRequest.Value)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password value to byte array")
		return
	}

	iv, err := hex.DecodeString(updatePasswordRequest.IV)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password IV to byte array")
		return
	}

	authTag, err := hex.DecodeString(updatePasswordRequest.AuthTag)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password auth tag to byte array")
		return
	}

	salt, err := hex.DecodeString(updatePasswordRequest.Salt)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform keygen salt to byte array")
		return
	}

	existingPassword.Name = updatePasswordRequest.NewName
	existingPassword.Value = value
	existingPassword.IV = iv
	existingPassword.AuthTag = authTag
	existingPassword.Salt = salt
	existingPassword.AssociatedURL = updatePasswordRequest.AssociatedURL

	result = phm.dbm.Db.Save(existingPassword)
	if result.RowsAffected == 0 {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorCreationFailed, "Could not create password")
		return
	}

	response := models.UpdatePasswordS2C{
		NewPassword: models.S2CPassword{
			Name:          existingPassword.Name,
			Value:         hex.EncodeToString(existingPassword.Value),
			IV:            hex.EncodeToString(existingPassword.IV),
			AuthTag:       hex.EncodeToString(existingPassword.AuthTag),
			Salt:          hex.EncodeToString(existingPassword.Salt),
			AssociatedURL: existingPassword.AssociatedURL,
		},
	}

	phm.logger.InfoContext(r.Context(), constants.MessagePasswordUpdated, constants.LogKeyPasswordName, existingPassword.Name)
	phm.responseWriter.WriteSuccessResponse(r.Context(), w, response)
}
