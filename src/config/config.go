package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type dbConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLmode  string
}

type jwtConfig struct {
	SecretKey       []byte
	AccessTokenExp  int // in hours
	RefreshTokenExp int // in hours
}

var (
	DBCfg  dbConfig
	JWTCfg jwtConfig
)

func InitConfig() {
	godotenv.Load()

	initDBConfig()
	initJWTConfig()
}

func initDBConfig() {
	port, err := strconv.Atoi(getEnvOrDie("DB_PORT"))
	if err != nil {
		log.Fatal("PORT must be int")
	}
	DBCfg = dbConfig{
		Host:     getEnvOrDie("DB_HOST"),
		Port:     port,
		User:     getEnvOrDie("DB_USER"),
		Password: getEnvOrDie("DB_PASSWORD"),
		Name:     getEnvOrDie("DB_NAME"),
		SSLmode:  getEnvElse("SSL_MODE", "disable"),
	}
}

func initJWTConfig() {
	accessTokenExp, err := strconv.Atoi(getEnvElse("ACCESS_TOKEN_EXP", "1"))
	if err != nil {
		log.Fatal("PORT must be int")
	}
	refreshTokenExp, err := strconv.Atoi(getEnvElse("REFRESH_TOKEN_EXP", "10"))
	if err != nil {
		log.Fatal("PORT must be int")
	}
	JWTCfg = jwtConfig{
		SecretKey:       []byte(getEnvOrDie("JWTSecretKey")),
		AccessTokenExp:  accessTokenExp,
		RefreshTokenExp: refreshTokenExp,
	}
}

func getEnvElse(key, other string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return other
}

func getEnvOrDie(key string) string {
	val, ok := os.LookupEnv(key)
	if ok {
		return val
	}
	log.Fatal("Config can not be set: ", ok)

	return ""
}
