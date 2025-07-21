// Utility functions

package main

import (
	"encoding/json"
	"net/http"
)

func writeErrorResponse(w http.ResponseWriter, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}
