// Handlers for the User subroute

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

var userHandlers []RequestHandlerStruct = []RequestHandlerStruct{
	{
		Handler: createUser,
		Method:  http.MethodPost,
		Route:   UserRouteRegister,
	},
	{
		Handler: loginUser,
		Method:  http.MethodPost,
		Route:   UserRouteLogin,
	},
	{
		Handler: jwtMiddleware(deleteUser),
		Method:  http.MethodDelete,
		Route:   UserRouteDelete,
	},
}

func registerUserHandlers(r *mux.Router) {
	subRouter := r.PathPrefix(SubrouteUser).Subrouter()
	for _, handler := range userHandlers {
		fmt.Printf("Added handler for route %s%s with method %s\n", SubrouteUser, handler.Route, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var createUserRequest CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&createUserRequest)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(createUserRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingUser User
	result := db.Where("username = ?", createUserRequest.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		writeErrorResponse(w, http.StatusConflict, ErrorUserExists, "Username already exists")
		return
	}

	passwordHash, err := hashPassword(createUserRequest.Password)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Failed to hash password")
		return
	}

	newUser := &User{
		Username:     createUserRequest.Username,
		PasswordHash: passwordHash,
	}

	result = db.Create(newUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorCreationFailed, "User creation failed")
		return
	}

	response := CreateUserSuccess{
		ID:       newUser.ID,
		Username: newUser.Username,
	}

	writeSuccessResponse(w, response, http.StatusCreated)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var loginRequest LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson, "")
		return
	}

	validationErrors := validateStruct(loginRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var user User
	result := db.Where("username = ?", loginRequest.Username).First(&user)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusUnauthorized, ErrorInvalidCredentials)
		return
	}

	if !checkPasswordHash(loginRequest.Password, user.PasswordHash) {
		writeErrorResponse(w, http.StatusUnauthorized, ErrorInvalidCredentials)
		return
	}

	token, err := generateJWT(user)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Failed to generate token")
		return
	}

	response := LoginSuccess{
		Token:    token,
		UserID:   user.ID,
		Username: user.Username,
	}
	writeSuccessResponse(w, response)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var existingUser User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusNotFound, ErrorNotFound)
		return
	}

	result = db.Delete(&existingUser)

	response := DeleteUserSuccess{
		UserID: existingUser.ID,
	}

	writeSuccessResponse(w, response)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updateUserRequest UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateUserRequest)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson, "")
		return
	}

	validationErrors := validateStruct(updateUserRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var existingUser User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusNotFound, ErrorNotFound)
		return
	}

	password, err := hashPassword(updateUserRequest.Password)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not hash password")
		return
	}

	existingUser.Username = updateUserRequest.Username
	existingUser.PasswordHash = password

	result = db.Save(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Could not update user DB entry")
	}

	response := UpdateUserSuccess{
		ID:       existingUser.ID,
		Username: existingUser.Username,
	}

	writeSuccessResponse(w, response)
}
