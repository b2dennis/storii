package apihandlers

import (
	"b2dennis/pwman-api/internal/auth"
	"b2dennis/pwman-api/internal/constants"
	"b2dennis/pwman-api/internal/middleware"
	"b2dennis/pwman-api/internal/models"
	"b2dennis/pwman-api/internal/utils"
	"b2dennis/pwman-api/internal/validation"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

type UserHandlerManager struct {
	jwt            *middleware.JWT
	jwtService     *auth.JWTService
	logger         *slog.Logger
	responseWriter *utils.ResponseWriter
	validator      *validation.Validator
}

func (uhm *UserHandlerManager) RegisterUserHandlers(r *mux.Router) {
	var userHandlers []models.RequestHandlerStruct = []models.RequestHandlerStruct{
		{
			Handler: uhm.createUser,
			Method:  http.MethodPost,
			Route:   constants.UserRouteRegister,
		},
		{
			Handler: uhm.loginUser,
			Method:  http.MethodPost,
			Route:   constants.UserRouteLogin,
		},
		{
			Handler: uhm.jwt.JwtMiddleware(uhm.deleteUser),
			Method:  http.MethodDelete,
			Route:   constants.UserRouteDelete,
		},
		{
			Handler: uhm.jwt.JwtMiddleware(uhm.updateUser),
			Method:  http.MethodPut,
			Route:   constants.UserRouteUpdate,
		},
	}

	subRouter := r.PathPrefix(constants.RouteUser).Subrouter()
	for _, handler := range userHandlers {
		uhm.logger.Info(constants.MessageRouteRegistered, constants.LogKeyRoute, constants.RouteUser, constants.LogKeySubroute, handler.Route, constants.LogKeyMethod, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

func (uhm *UserHandlerManager) createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var createUserRequest models.CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&createUserRequest)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson)
		return
	}

	validationErrors := uhm.validator.ValidateStruct(createUserRequest)
	if len(validationErrors) > 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
		return
	}

	var existingUser models.User
	result := db.Where("username = ?", createUserRequest.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusConflict, constants.ErrorUserExists, "Username already exists")
		return
	}

	passwordHash, err := auth.HashPassword(createUserRequest.Password)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Failed to hash password")
		return
	}

	newUser := &models.User{
		Username:     createUserRequest.Username,
		PasswordHash: passwordHash,
	}

	result = db.Create(newUser)
	if result.RowsAffected == 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorCreationFailed, "User creation failed")
		return
	}

	response := models.CreateUserSuccess{
		ID:       newUser.ID,
		Username: newUser.Username,
	}

	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUsername, response.Username))
	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUserID, response.ID))

	uhm.logger.InfoContext(r.Context(), constants.MessageUserCreated)
	uhm.responseWriter.WriteSuccessResponse(r.Context(), w, response, http.StatusCreated)
}

func (uhm *UserHandlerManager) loginUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var loginRequest models.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson, "")
		return
	}

	validationErrors := uhm.validator.ValidateStruct(loginRequest)
	if len(validationErrors) > 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var user models.User
	result := db.Where("username = ?", loginRequest.Username).First(&user)
	if result.RowsAffected == 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusUnauthorized, constants.ErrorInvalidCredentials)
		return
	}

	if !auth.CheckPasswordHash(loginRequest.Password, user.PasswordHash) {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusUnauthorized, constants.ErrorInvalidCredentials)
		return
	}

	token, err := uhm.jwtService.GenerateJWT(user)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Failed to generate token")
		return
	}

	response := models.LoginSuccess{
		Token:    token,
		UserID:   user.ID,
		Username: user.Username,
	}

	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUsername, user.Username))
	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyUserID, user.ID))

	uhm.logger.InfoContext(r.Context(), constants.MessageUserCreated)
	uhm.responseWriter.WriteSuccessResponse(r.Context(), w, response)
}

func (uhm *UserHandlerManager) deleteUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var existingUser models.User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	result = db.Delete(&existingUser)

	response := models.DeleteUserSuccess{
		UserID: existingUser.ID,
	}

	uhm.logger.InfoContext(r.Context(), constants.MessageUserDeleted)
	uhm.responseWriter.WriteSuccessResponse(r.Context(), w, response)
}

func (uhm *UserHandlerManager) updateUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	userIDStr := r.Header.Get(constants.AuthHeaderUserID)
	UserID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidID, "Invalid user ID in token")
		return
	}

	var updateUserRequest models.UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateUserRequest)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorInvalidJson, "")
		return
	}

	validationErrors := uhm.validator.ValidateStruct(updateUserRequest)
	if len(validationErrors) > 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusBadRequest, constants.ErrorValidation, strings.Join(validationErrors, "; "))
	}

	var existingUser models.User
	result := db.Where("id = ?", UserID).First(&existingUser)
	if result.RowsAffected == 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusNotFound, constants.ErrorNotFound)
		return
	}

	password, err := auth.HashPassword(updateUserRequest.Password)
	if err != nil {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not hash password")
		return
	}

	existingUser.Username = updateUserRequest.Username
	existingUser.PasswordHash = password

	result = db.Save(&existingUser)
	if result.RowsAffected == 0 {
		uhm.responseWriter.WriteErrorResponse(r.Context(), w, http.StatusInternalServerError, constants.ErrorInternalServer, "Could not update user DB entry")
	}

	response := models.UpdateUserSuccess{
		ID:       existingUser.ID,
		Username: existingUser.Username,
	}

	uhm.logger.InfoContext(r.Context(), constants.MessageUserUpdated, constants.LogKeyNewUsername, existingUser.Username)
	uhm.responseWriter.WriteSuccessResponse(r.Context(), w, response)
}
