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

func writeSuccessResponse(w http.ResponseWriter, data any, statusCodeOpt ...int) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	statusCode := http.StatusOK
	if len(statusCodeOpt) > 0 {
		statusCode = statusCodeOpt[0]
	}
	w.WriteHeader(statusCode)

	json.NewEncoder(w).Encode(data)
}
