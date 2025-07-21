// Handlers for the Password subroute

package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

var passwordHandlers []RequestHandlerStruct = []RequestHandlerStruct{
	{
		Handler: jwtMiddleware(getPasswords),
		Method:  "GET",
		Route:   "",
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

	if len(storedPasswords) == 0 {
		writeErrorResponse(w, http.StatusInternalServerError, ErrorNotFound, "no passwords found")
		return
	}

	for _, password := range storedPasswords {
		fmt.Fprintf(w, "%s\n", password.Value)
	}
}
