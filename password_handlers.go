// Handlers for the Password subroute

package main

import (
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
}

func registerPasswordHandlers(r *mux.Router) {
	subRouter := r.PathPrefix(SubroutePassword).Subrouter()
	for _, handler := range passwordHandlers {
		fmt.Printf("Added handler for route %s%s with method %s\n", SubroutePassword, handler.Route, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
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
			Value:         storedPassword.Value,
			IV:            storedPassword.IV,
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

	newPassword := &StoredPassword{
		UserID:        uint(UserID),
		Name:          addPasswordRequest.Name,
		Value:         addPasswordRequest.Value,
		IV:            addPasswordRequest.IV,
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
			Value:         newPassword.Value,
			IV:            newPassword.IV,
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
