// Utility functions

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

func writeErrorResponse(ctx context.Context, w http.ResponseWriter, statusCode int, errorCode string, messageOpt ...string) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(statusCode)
	message := ""
	if len(messageOpt) > 0 {
		message = messageOpt[0]
	}

	contextLogger.ErrorContext(ctx, message, "statusCode", strconv.Itoa(statusCode), "errorCode", errorCode)

	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}

func writeSuccessResponse(ctx context.Context, w http.ResponseWriter, data any, statusCodeOpt ...int) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	statusCode := http.StatusOK
	if len(statusCodeOpt) > 0 {
		statusCode = statusCodeOpt[0]
	}
	w.WriteHeader(statusCode)

	contextLogger.InfoContext(ctx, ResponseSuccess, "statusCode", strconv.Itoa(statusCode))

	json.NewEncoder(w).Encode(SuccessResponse{
		Data:    data,
		Message: ResponseSuccess,
	})
}
