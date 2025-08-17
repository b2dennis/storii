package server

import (
	"github.com/b2dennis/stori/internal/apihandlers"
	"github.com/b2dennis/stori/internal/auth"
	"github.com/b2dennis/stori/internal/config"
	"github.com/b2dennis/stori/internal/db"
	"github.com/b2dennis/stori/internal/logging"
	"github.com/b2dennis/stori/internal/middleware"
	"github.com/b2dennis/stori/internal/utils"
	"github.com/b2dennis/stori/internal/validation"
	"log/slog"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type Server struct {
	config         *config.Config
	logger         *slog.Logger
	log            *middleware.Log
	validator      *validation.Validator
	router         *mux.Router
	responseWriter *utils.ResponseWriter
	rateLimit      *middleware.RateLimit
	jwt            *middleware.JWT
	jwtService     *auth.JWTService
	dbm            *db.DbManager
}

func NewServer() Server {
	godotenv.Load()
	config := config.LoadConfig()

	dbm := db.NewDbManager(config)

	logger := logging.NewLogger(config)
	log := middleware.NewLog(logger)
	responseWriter := utils.NewResponseWriter(logger)

	jwtService := auth.NewJWTService(config)

	rateLimit := middleware.NewRateLimit(logger, responseWriter)
	jwt := middleware.NewJWT(jwtService, responseWriter)

	validator := validation.NewValidator()

	router := mux.NewRouter()
	router.Use(middleware.ContextMiddleware, log.LoggingMiddleware, rateLimit.RateLimitMiddleware)

	return Server{
		config:         config,
		logger:         logger,
		validator:      validator,
		router:         router,
		log:            log,
		responseWriter: responseWriter,
		rateLimit:      rateLimit,
		jwt:            jwt,
		jwtService:     jwtService,
		dbm:            dbm,
	}
}

func (s *Server) Run() {
	s.registerHandlers()

	http.ListenAndServe(s.config.Address, handlers.CORS(
		handlers.AllowCredentials(),
		handlers.AllowedHeaders([]string{"GET", "POST", "PUT", "DELETE"}),
		handlers.AllowedHeaders([]string{"Authorization"}),
		handlers.AllowedOrigins([]string{"*"}),
	)(s.router))
}

func (s *Server) registerHandlers() {
	passwordHandlerManager := apihandlers.NewPasswordHandlerManager(s.jwt, s.logger, s.responseWriter, s.validator, s.dbm)
	passwordHandlerManager.RegisterPasswordHandlers(s.router)

	userHandlerManager := apihandlers.NewUserHandlerManager(s.jwt, s.jwtService, s.logger, s.responseWriter, s.validator, s.dbm)
	userHandlerManager.RegisterUserHandlers(s.router)
}
