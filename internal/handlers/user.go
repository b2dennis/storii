package handlers

import (
	"b2dennis/pwman-api/internal/constants"
	"b2dennis/pwman-api/internal/models"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

var userHandlers []models.RequestHandlerStruct = []models.RequestHandlerStruct{
	{
		Handler: createUser,
		Method:  http.MethodPost,
		Route:   constants.UserRouteRegister,
	},
	{
		Handler: loginUser,
		Method:  http.MethodPost,
		Route:   constants.UserRouteLogin,
	},
	{
		Handler: jwtMiddleware(deleteUser),
		Method:  http.MethodDelete,
		Route:   constants.UserRouteDelete,
	},
	{
		Handler: jwtMiddleware(updateUser),
		Method:  http.MethodPut,
		Route:   constants.UserRouteUpdate,
	},
}

func registerUserHandlers(r *mux.Router) {
	subRouter := r.PathPrefix(constants.RouteUser).Subrouter()
	for _, handler := range userHandlers {
		contextLogger.Info(constants.MessageRouteRegistered, constants.LogKeyRoute, constants.RouteUser, constants.LogKeySubroute, handler.Route, constants.LogKeyMethod, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var createUserRequest CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&createUserRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := validateStruct(createUserRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingUser User
	result := db.Where("username = ?", createUserRequest.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		writeErrorResponse(r.Context(), w, http.StatusConflict, constants.ErrorUserExists, "Username already exists")
		return
	}

	passwordHash, err := hashPassword(createUserRequest.Password)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Failed to hash password")
		return
	}

	newUser := &User{
		Username:     createUserRequest.Username,
		PasswordHash: passwordHash,
	}

	result = db.Create(newUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorCreationFailed, "User creation failed")
		return
	}

	response := CreateUserSuccess{
		ID:       newUser.ID,
		Username: newUser.Username,
	}

	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUsername, response.Username))
	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUserID, response.ID))

	contextLogger.InfoContext(r.Context(), constants.MessageUserCreated)
	writeSuccessResponse(r.Context(), w, response, http.StatusCreated)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var loginRequest LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson, "")
		return
	}

	validationErrors := validateStruct(loginRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var user User
	result := db.Where("username = ?", loginRequest.Username).First(&user)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusUnauthorized, constants.ErrorInvalidCredentials)
		return
	}

	if !checkPasswordHash(loginRequest.Password, user.PasswordHash) {
		writeErrorResponse(r.Context(), w, http.StatusUnauthorized, constants.ErrorInvalidCredentials)
		return
	}

	token, err := generateJWT(user)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Failed to generate token")
		return
	}

	response := LoginSuccess{
		Token:    token,
		UserID:   user.ID,
		Username: user.Username,
	}

	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUsername, user.Username))
	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUserID, user.ID))

	contextLogger.InfoContext(r.Context(), constants.MessageUserCreated)
	writeSuccessResponse(r.Context(), w, response)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var existingUser User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	result = db.Delete(&existingUser)

	response := DeleteUserSuccess{
		UserID: existingUser.ID,
	}

	contextLogger.InfoContext(r.Context(), constants.MessageUserDeleted)
	writeSuccessResponse(r.Context(), w, response)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updateUserRequest UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateUserRequest)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson, "")
		return
	}

	validationErrors := validateStruct(updateUserRequest)
	if len(validationErrors) > 0 {
		writeErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var existingUser User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	password, err := hashPassword(updateUserRequest.Password)
	if err != nil {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not hash password")
		return
	}

	existingUser.Username = updateUserRequest.Username
	existingUser.PasswordHash = password

	result = db.Save(&existingUser)
	if result.RowsAffected == 0 {
		writeErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not update user DB entry")
	}

	response := UpdateUserSuccess{
		ID:       existingUser.ID,
		Username: existingUser.Username,
	}

	contextLogger.InfoContext(r.Context(), constants.MessageUserUpdated, constants.LogKeyNewUsername, existingUser.Username)
	writeSuccessResponse(r.Context(), w, response)
}
