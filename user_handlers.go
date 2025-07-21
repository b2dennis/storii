// Handlers for the User subroute

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
		Method:  http.MethodPost,
		Route:   "",
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
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = nil
	err = json.NewEncoder(w).Encode(CreateUserResponse{ID: newUser.ID, Username: newUser.Username})
	if err != nil {
		fmt.Println("Error encoding user to JSON")
		return
	}
}
