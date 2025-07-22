// Handlers for the User subroute

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

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

	var requestBody CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson)
		return
	}

	if requestBody.Username == "" || requestBody.Password == "" {
		writeErrorResponse(w, http.StatusBadRequest, ErrorUserPassMissing, "Username and password are required")
		return
	}

	var existingUser User
	result := db.Where("username = ?", requestBody.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		writeErrorResponse(w, http.StatusConflict, ErrorUserExists, "Username already exists")
		return
	}

	passwordHash, err := hashPassword(requestBody.Password)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorInternalServer, "Failed to hash password")
		return
	}

	newUser := &User{
		Username:     requestBody.Username,
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

	var requestBody LoginRequest
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, ErrorInvalidJson, "")
		return
	}

	if requestBody.Username == "" || requestBody.Password == "" {
		writeErrorResponse(w, http.StatusBadRequest, ErrorUserPassMissing, "Username and password are required")
		return
	}

	var user User
	result := db.Where("username = ?", requestBody.Username).First(&user)
	if result.RowsAffected == 0 {
		writeErrorResponse(w, http.StatusUnauthorized, ErrorInvalidCredentials)
		return
	}

	if !checkPasswordHash(requestBody.Password, user.PasswordHash) {
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
