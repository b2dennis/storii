package constants

// Env Var Names
const (
	VarAddress   = "ADDRESS"
	VarJWTSecret = "JWTSECRET"
	VarJWTExpiry = "JWTEXPIRY"
	VarLogOutput = "LOGOUTPUT"
	VarDBHost    = "DBHOST"
	VarDBName    = "DBNAME"
	VarDBPort    = "DBPORT"
	VarDBUser    = "DBUSER"
	VarDBPass    = "DBPASS"
)

// Env Var Defaults
const (
	DefaultAddress   = ":9999"
	DefaultJWTSecret = "b2dennis"
	DefaultJWTExpiry = "24"
	DefaultLogOutput = "stdout"
	DefaultDBHost    = "localhost"
	DefaultDBName    = "postgres"
	DefaultDBPort    = "5432"
	DefaultDBUser    = "default_user"
	DefaultDBPass    = "default_pass"
)
