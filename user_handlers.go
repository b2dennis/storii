package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

var userHandlers []RequestHandlerStruct = []RequestHandlerStruct{
	{
		Handler: createUser,
		Method:  "POST",
		Route:   "/",
	},
}

func registerUserHandlers(r *mux.Router) {
	subRouter := r.PathPrefix("/user").Subrouter()
	for _, handler := range userHandlers {
		fmt.Printf("Added handler for route /user%s with method %s\n", handler.Route, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var requestBody CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
	}

	hasher := sha512.New()
	hasher.Write([]byte(requestBody.Password))

	passwordHash := hasher.Sum(nil)

	newUser := User{
		Username:     requestBody.Username,
		PasswordHash: hex.EncodeToString(passwordHash),
	}

	result := db.Create(&newUser)
	if result.RowsAffected == 0 {
		http.Error(w, "User creation failed", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully created user %s", requestBody.Username)
}
