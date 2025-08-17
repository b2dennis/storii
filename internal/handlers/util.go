package handlers

import (
	"log/slog"
	"net/http"

	"github.com/b2dennis/storii/internal/constants"
	"github.com/b2dennis/storii/internal/models"
	"github.com/gorilla/mux"
)

type UtilHandlerManager struct {
	logger *slog.Logger
}

func NewUtilHandlerManager(logger *slog.Logger) *UtilHandlerManager {
	return &UtilHandlerManager{
		logger: logger,
	}
}

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

func Ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("200 OK"))
}
