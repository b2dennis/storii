package server

import (
	"github.com/b2dennis/storii/internal/auth"
	"github.com/b2dennis/storii/internal/config"
	"github.com/b2dennis/storii/internal/db"
	"github.com/b2dennis/storii/internal/handlers"
	"github.com/b2dennis/storii/internal/logging"
	"github.com/b2dennis/storii/internal/middleware"
	"github.com/b2dennis/storii/internal/utils"
	"github.com/b2dennis/storii/internal/validation"
	"log/slog"
	"net/http"

	ghandlers "github.com/gorilla/handlers"
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

	http.ListenAndServe(s.config.Address, ghandlers.CORS(
		ghandlers.AllowCredentials(),
		ghandlers.AllowedHeaders([]string{"GET", "POST", "PUT", "DELETE"}),
		ghandlers.AllowedHeaders([]string{"Authorization"}),
		ghandlers.AllowedOrigins([]string{"*"}),
	)(s.router))
}

func (s *Server) registerHandlers() {
	passwordHandlerManager := handlers.NewPasswordHandlerManager(s.jwt, s.logger, s.responseWriter, s.validator, s.dbm)
	passwordHandlerManager.RegisterPasswordHandlers(s.router)

	userHandlerManager := handlers.NewUserHandlerManager(s.jwt, s.jwtService, s.logger, s.responseWriter, s.validator, s.dbm)
	userHandlerManager.RegisterUserHandlers(s.router)
}
