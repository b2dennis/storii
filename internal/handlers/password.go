package handlers

import (
	"b2dennis/pwman-api/internal/constants"
	"b2dennis/pwman-api/internal/middleware"
	"b2dennis/pwman-api/internal/models"
	"b2dennis/pwman-api/internal/utils"
	"encoding/hex"
	"encoding/json"
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
}

func (phm *PasswordHandlerManager) registerPasswordHandlers(r *mux.Router) {
	var passwordHandlers []models.RequestHandlerStruct = []models.RequestHandlerStruct{
		{
			Handler: phm.jwt.JwtMiddleware(phm.getPasswords),
			Method:  http.MethodGet,
			Route:   constants.PasswordRouteFetch,
		},
		{
			Handler: phm.jwt.JwtMiddleware(addPassword),
			Method:  http.MethodPost,
			Route:   constants.PasswordRouteAdd,
		},
		{
			Handler: phm.jwt.JwtMiddleware(deletePassword),
			Method:  http.MethodDelete,
			Route:   constants.PasswordRouteDelete,
		},
		{
			Handler: phm.jwt.JwtMiddleware(updatePassword),
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

func (phm *PasswordHandlerManager) getPasswords(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var storedPasswords []models.StoredPassword
	db.Where("user_id = ?", uint(UserID)).Find(&storedPasswords)

	responsePasswords := make([]models.ResponsePassword, len(storedPasswords))

	for i, storedPassword := range storedPasswords {
		responsePasswords[i] = models.ResponsePassword{
			Name:          storedPassword.Name,
			Value:         hex.EncodeToString(storedPassword.Value),
			IV:            hex.EncodeToString(storedPassword.IV),
			AuthTag:       hex.EncodeToString(storedPassword.AuthTag),
			Salt:          hex.EncodeToString(storedPassword.Salt),
			AssociatedURL: storedPassword.AssociatedURL,
		}
	}

	response := models.GetPasswordsSuccess{
		Passwords: responsePasswords,
	}

	phm.logger.InfoContext(r.Context(), constants.MessagePasswordsFetched)
	phm.responseWriter.WriteSuccessResponse(r.Context(), w, response, http.StatusOK)
}

func (phm *PasswordHandlerManager) addPassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var addPasswordRequest models.AddPasswordRequest
	err = json.NewDecoder(r.Body).Decode(&addPasswordRequest)
	if err != nil {
		phm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(addPasswordRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existing StoredPassword
	result := db.Where("user_id = ? AND name = ?", UserID, addPasswordRequest.Name).First(&existing)
	if result.RowsAffected > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorDuplicatePassword)
		return
	}

	value, err := hex.DecodeString(addPasswordRequest.Value)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password value to byte array")
		return
	}

	iv, err := hex.DecodeString(addPasswordRequest.IV)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password IV to byte array")
		return
	}

	authTag, err := hex.DecodeString(addPasswordRequest.AuthTag)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password auth tag to byte array")
		return
	}

	salt, err := hex.DecodeString(addPasswordRequest.Salt)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform keygen salt to byte array")
		return
	}

	newPassword := &StoredPassword{
		UserID:        uint(UserID),
		Name:          addPasswordRequest.Name,
		Value:         value,
		IV:            iv,
		AuthTag:       authTag,
		Salt:          salt,
		AssociatedURL: addPasswordRequest.AssociatedURL,
	}

	result = db.Create(newPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorCreationFailed, "Could not create password")
		return
	}

	response := AddPasswordSuccess{
		NewPassword: ResponsePassword{
			Name:          newPassword.Name,
			Value:         hex.EncodeToString(newPassword.Value),
			IV:            hex.EncodeToString(newPassword.IV),
			AuthTag:       hex.EncodeToString(newPassword.AuthTag),
			Salt:          hex.EncodeToString(newPassword.Salt),
			AssociatedURL: newPassword.AssociatedURL,
		},
	}

	contextLogger.InfoContext(r.Context(), constants.MessagePasswordCreated, constants.LogKeyPasswordName, newPassword.Name)
	writeSuccessResponse(r.Context(), w, response, http.StatusCreated)
}

func deletePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var deletePasswordRequest DeletePasswordRequest
	err = json.NewDecoder(r.Body).Decode(&deletePasswordRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(deletePasswordRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingPassword StoredPassword
	result := db.Where("user_id = ? AND name = ?", UserID, deletePasswordRequest.Name).First(&existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	result = db.Delete(&existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Failed to delete password")
		return
	}

	response := DeletePasswordSuccess{
		Name: existingPassword.Name,
	}

	contextLogger.InfoContext(r.Context(), constants.MessagePasswordDeleted, constants.LogKeyPasswordName, existingPassword.Name)
	writeSuccessResponse(r.Context(), w, response)
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	UserIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(UserIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updatePasswordRequest UpdatePasswordRequest
	err = json.NewDecoder(r.Body).Decode(&updatePasswordRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(updatePasswordRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingPassword StoredPassword
	result := db.Where("user_id = ? AND name = ?", UserID, updatePasswordRequest.Name).First(&existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	value, err := hex.DecodeString(updatePasswordRequest.Value)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password value to byte array")
		return
	}

	iv, err := hex.DecodeString(updatePasswordRequest.IV)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password IV to byte array")
		return
	}

	authTag, err := hex.DecodeString(updatePasswordRequest.AuthTag)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform password auth tag to byte array")
		return
	}

	salt, err := hex.DecodeString(updatePasswordRequest.Salt)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not transform keygen salt to byte array")
		return
	}

	existingPassword.Name = updatePasswordRequest.NewName
	existingPassword.Value = value
	existingPassword.IV = iv
	existingPassword.AuthTag = authTag
	existingPassword.Salt = salt
	existingPassword.AssociatedURL = updatePasswordRequest.AssociatedURL

	result = db.Save(existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorCreationFailed, "Could not create password")
		return
	}

	response := UpdatePasswordSuccess{
		NewPassword: ResponsePassword{
			Name:          existingPassword.Name,
			Value:         hex.EncodeToString(existingPassword.Value),
			IV:            hex.EncodeToString(existingPassword.IV),
			AuthTag:       hex.EncodeToString(existingPassword.AuthTag),
			Salt:          hex.EncodeToString(existingPassword.Salt),
			AssociatedURL: existingPassword.AssociatedURL,
		},
	}

	contextLogger.InfoContext(r.Context(), constants.MessagePasswordUpdated, constants.LogKeyPasswordName, existingPassword.Name)
	writeSuccessResponse(r.Context(), w, response)
}
