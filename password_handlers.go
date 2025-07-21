package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

var passwordHandlers []RequestHandlerStruct = []RequestHandlerStruct{
	{
		Handler: getPasswords,
		Method:  "GET",
		Route:   "/{user_id}",
	},
}

func registerPasswordHandlers(r *mux.Router) {
	subRouter := r.PathPrefix("/password").Subrouter()
	for _, handler := range passwordHandlers {
		fmt.Printf("Added handler for route /password%s with method %s\n", handler.Route, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
	}
}

func getPasswords(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	UserID, err := strconv.ParseUint(vars["user_id"], 10, 64)
	if err != nil {
		fmt.Fprint(w, "User did not pass a valid UInt")
		return
	}
	fmt.Fprintf(w, "Passwords for user %d", UserID)
	var storedPasswords []StoredPassword
	db.Where("user_id = ?", uint(UserID)).Find(&storedPasswords)

	for _, password := range storedPasswords {
		fmt.Fprintf(w, "%s\n", password.Value)
	}
}
