package server

import (
	"b2dennis/pwman-api/internal/apihandlers"
	"b2dennis/pwman-api/internal/auth"
	"b2dennis/pwman-api/internal/config"
	"b2dennis/pwman-api/internal/logging"
	"b2dennis/pwman-api/internal/middleware"
	"b2dennis/pwman-api/internal/utils"
	"b2dennis/pwman-api/internal/validation"
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
}

func NewServer() Server {
	godotenv.Load()
	config := config.LoadConfig()

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

func main() {
	contextLogger.Info("Initializing DB connection")
	var err error
	db, err = gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %s", config.DBPath))
	}

	contextLogger.Info("Running DB migrations")
	runDbMigrations()

}

func (s *Server) registerHandlers() {
	passwordHandlerManager := apihandlers.NewPasswordHandlerManager(s.jwt, s.logger, s.responseWriter, s.validator)
	passwordHandlerManager.RegisterPasswordHandlers(s.router)

	userHandlerManager := apihandlers.NewUserHandlerManager(s.jwt, s.jwtService, s.logger, s.responseWriter, s.validator)
	userHandlerManager.RegisterUserHandlers(s.router)
}

func runDbMigrations() {
	db.AutoMigrate(&StoredPassword{})
	db.AutoMigrate(&User{})
}
