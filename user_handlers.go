// Handlers for the User subroute

package main

import (
	"context"
	"encoding/json"
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
	{
		Handler: jwtMiddleware(updateUser),
		Method:  http.MethodPut,
		Route:   UserRouteUpdate,
	},
}

func registerUserHandlers(r *mux.Router) {
	subRouter := r.PathPrefix(RouteUser).Subrouter()
	for _, handler := range userHandlers {
		contextLogger.Info(MessageRouteRegistered, LogKeyRoute, RouteUser, LogKeySubroute, handler.Route, LogKeyMethod, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var createUserRequest CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&createUserRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(createUserRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingUser User
	result := db.Where("username = ?", createUserRequest.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		writeErrorResponse(r.Context(), w, http.StatusConflict, ErrorUserExists, "Username already exists")
		return
	}

	passwordHash, err := hashPassword(createUserRequest.Password)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, ErrorInternalServer, "Failed to hash password")
		return
	}

	newUser := &User{
		Username:     createUserRequest.Username,
		PasswordHash: passwordHash,
	}

	result = db.Create(newUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, ErrorCreationFailed, "User creation failed")
		return
	}

	response := CreateUserSuccess{
		ID:       newUser.ID,
		Username: newUser.Username,
	}

	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUsername, response.Username))
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUserID, response.ID))

	contextLogger.InfoContext(r.Context(), MessageUserCreated)
	writeSuccessResponse(r.Context(), w, response, http.StatusCreated)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var loginRequest LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorInvalidJson, "")
		return
	}

	validationErrors := validateStruct(loginRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var user User
	result := db.Where("username = ?", loginRequest.Username).First(&user)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusUnauthorized, ErrorInvalidCredentials)
		return
	}

	if !checkPasswordHash(loginRequest.Password, user.PasswordHash) {
		writeErrorResponse(r.Context(), w, http.StatusUnauthorized, ErrorInvalidCredentials)
		return
	}

	token, err := generateJWT(user)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, ErrorInternalServer, "Failed to generate token")
		return
	}

	response := LoginSuccess{
		Token:    token,
		UserID:   user.ID,
		Username: user.Username,
	}

	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUsername, user.Username))
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUserID, uint64(user.ID)))

	contextLogger.InfoContext(r.Context(), MessageUserCreated)
	writeSuccessResponse(r.Context(), w, response)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var existingUser User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusNotFound, ErrorNotFound)
		return
	}

	result = db.Delete(&existingUser)

	response := DeleteUserSuccess{
		UserID: existingUser.ID,
	}

	contextLogger.InfoContext(r.Context(), MessageUserDeleted)
	writeSuccessResponse(r.Context(), w, response)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updateUserRequest UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateUserRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorInvalidJson, "")
		return
	}

	validationErrors := validateStruct(updateUserRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var existingUser User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusNotFound, ErrorNotFound)
		return
	}

	password, err := hashPassword(updateUserRequest.Password)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, ErrorInternalServer, "Could not hash password")
		return
	}

	existingUser.Username = updateUserRequest.Username
	existingUser.PasswordHash = password

	result = db.Save(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, ErrorInternalServer, "Could not update user DB entry")
	}

	response := UpdateUserSuccess{
		ID:       existingUser.ID,
		Username: existingUser.Username,
	}

	contextLogger.InfoContext(r.Context(), MessageUserUpdated, LogKeyNewUsername, existingUser.Username)
	writeSuccessResponse(r.Context(), w, response)
}
