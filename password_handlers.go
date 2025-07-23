// Handlers for the Password subroute

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

var passwordHandlers []RequestHandlerStruct = []RequestHandlerStruct{
	{
		Handler: jwtMiddleware(getPasswords),
		Method:  http.MethodGet,
		Route:   PasswordRouteFetch,
	},
	{
		Handler: jwtMiddleware(addPassword),
		Method:  http.MethodPost,
		Route:   PasswordRouteAdd,
	},
	{
		Handler: jwtMiddleware(deletePassword),
		Method:  http.MethodDelete,
		Route:   PasswordRouteDelete,
	},
	{
		Handler: jwtMiddleware(updatePassword),
		Method:  http.MethodPut,
		Route:   PasswordRouteUpdate,
	},
}

func registerPasswordHandlers(r *mux.Router) {
	subRouter := r.PathPrefix(SubroutePassword).Subrouter()
	for _, handler := range passwordHandlers {
		logger.Info(fmt.Sprintf("Added handler for route %s%s with method %s\n", SubroutePassword, handler.Route, handler.Method))
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

func getPasswords(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var storedPasswords []StoredPassword
	db.Where("user_id = ?", uint(UserID)).Find(&storedPasswords)

	responsePasswords := make([]ResponsePassword, len(storedPasswords))

	for i, storedPassword := range storedPasswords {
		responsePasswords[i] = ResponsePassword{
			Name:          storedPassword.Name,
			Value:         hex.EncodeToString(storedPassword.Value),
			IV:            hex.EncodeToString(storedPassword.IV),
			AuthTag:       hex.EncodeToString(storedPassword.AuthTag),
			Salt:          hex.EncodeToString(storedPassword.Salt),
			AssociatedURL: storedPassword.AssociatedURL,
		}
	}

	response := GetPasswordsSuccess{
		Passwords: responsePasswords,
	}

	writeSuccessResponse(w, response, http.StatusOK)
}

func addPassword(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var addPasswordRequest AddPasswordRequest
	err = json.NewDecoder(r.Body).Decode(&addPasswordRequest)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(addPasswordRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existing StoredPassword
	result := db.Where("user_id = ? AND name = ?", UserID, addPasswordRequest.Name).First(&existing)
	if result.RowsAffected > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorDuplicatePassword)
		return
	}

	value, err := hex.DecodeString(addPasswordRequest.Value)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform password value to byte array")
		return
	}

	iv, err := hex.DecodeString(addPasswordRequest.IV)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform password IV to byte array")
		return
	}

	authTag, err := hex.DecodeString(addPasswordRequest.AuthTag)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform password auth tag to byte array")
		return
	}

	salt, err := hex.DecodeString(addPasswordRequest.Salt)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform keygen salt to byte array")
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
		writeErrorResponse(w, http.StatusInternalServerError, ErrorCreationFailed, "Could not create password")
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

	writeSuccessResponse(w, response, http.StatusCreated)
}

func deletePassword(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var deletePasswordRequest DeletePasswordRequest
	err = json.NewDecoder(r.Body).Decode(&deletePasswordRequest)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(deletePasswordRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingPassword StoredPassword
	result := db.Where("user_id = ? AND name = ?", UserID, deletePasswordRequest.Name).First(&existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusNotFound, ErrorNotFound)
		return
	}

	result = db.Delete(&existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Failed to delete password")
		return
	}

	response := DeletePasswordSuccess{
		Name: existingPassword.Name,
	}

	writeSuccessResponse(w, response)
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	UserIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(UserIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updatePasswordRequest UpdatePasswordRequest
	err = json.NewDecoder(r.Body).Decode(&updatePasswordRequest)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(updatePasswordRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingPassword StoredPassword
	result := db.Where("user_id = ? AND name = ?", UserID, updatePasswordRequest.Name).First(&existingPassword)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusNotFound, ErrorNotFound)
		return
	}

	value, err := hex.DecodeString(updatePasswordRequest.Value)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform password value to byte array")
		return
	}

	iv, err := hex.DecodeString(updatePasswordRequest.IV)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform password IV to byte array")
		return
	}

	authTag, err := hex.DecodeString(updatePasswordRequest.AuthTag)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform password auth tag to byte array")
		return
	}

	salt, err := hex.DecodeString(updatePasswordRequest.Salt)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not transform keygen salt to byte array")
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
		writeErrorResponse(w, http.StatusInternalServerError, ErrorCreationFailed, "Could not create password")
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

	writeSuccessResponse(w, response)
}
