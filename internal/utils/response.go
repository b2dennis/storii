package utils

import (
	"b2dennis/pwman-api/internal/constants"
	"b2dennis/pwman-api/internal/models"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

type ResponseWriter struct {
	logger *slog.Logger
}

func (r *ResponseWriter) WriteErrorResponse(ctx context.Context, w http.ResponseWriter, statusCode int, errorCode string, messageOpt ...string) {
	w.Header().Set("Content-Type", constants.ContentTypeJSON)
	w.WriteHeader(statusCode)
	message := ""
	if len(messageOpt) > 0 {
		message = messageOpt[0]
	}

	r.logger.ErrorContext(ctx, message, "statusCode", strconv.Itoa(statusCode), "errorCode", errorCode)

	json.NewEncoder(w).Encode(models.ErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}

func (r *ResponseWriter) WriteSuccessResponse(ctx context.Context, w http.ResponseWriter, data any, statusCodeOpt ...int) {
	w.Header().Set("Content-Type", constants.ContentTypeJSON)
	statusCode := http.StatusOK
	if len(statusCodeOpt) > 0 {
		statusCode = statusCodeOpt[0]
	}
	w.WriteHeader(statusCode)

	r.logger.InfoContext(ctx, constants.ResponseSuccess, "statusCode", strconv.Itoa(statusCode))

	json.NewEncoder(w).Encode(models.SuccessResponse{
		Data:    data,
		Message: constants.ResponseSuccess,
	})
}
