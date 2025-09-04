package handlers

import (
	"log/slog"
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"github.com/gorilla/mux"
)

// Helper struct to initialize util handlers.
type UtilHandlerManager struct {
	logger *slog.Logger
}

// Constructor for UtilHandlerManager
func NewUtilHandlerManager(logger *slog.Logger) *UtilHandlerManager {
	return &UtilHandlerManager{
		logger: logger,
	}
}

// Helper to register all util handlers.
func (uhm *UtilHandlerManager) RegisterUtilHandlers(r *mux.Router) {
	var utilHandlers []models.RequestHandlerStruct = []models.RequestHandlerStruct{
		{
			Handler: Ping,
			Method:  http.MethodGet,
			Route:   constants.UtilRoutePing,
		},
	}

	subRouter := r.PathPrefix(constants.RouteUtil).Subrouter()
	for _, handler := range utilHandlers {
		uhm.logger.Info(constants.MessageRouteRegistered, constants.LogKeyRoute, constants.RouteUtil, constants.LogKeySubroute, handler.Route, constants.LogKeyMethod, handler.Method)
		subRouter.HandleFunc(handler.Route, handler.Handler).Methods(handler.Method)
		subRouter.HandleFunc(handler.Route+"/", handler.Handler).Methods(handler.Method)
	}
}

// Handler that just returns a success response.
func Ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(constants.PingRouteSuccessResponse))
}
