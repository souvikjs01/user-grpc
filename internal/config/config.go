package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Database DatabaseConfig
	JWT      JWTConfig
	Server   ServerConfig
}

type DatabaseConfig struct {
	DB_URL string
}

type JWTConfig struct {
	Secret             string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
}

type ServerConfig struct {
	Port string
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("failed to load env file")
	}
	return &Config{
		Database: DatabaseConfig{
			DB_URL: getEnv("DATABASE_URL"),
		},
		JWT: JWTConfig{
			Secret:             getEnv("JWT_SECRET"),
			AccessTokenExpiry:  time.Hour * 24,     // 1 day
			RefreshTokenExpiry: time.Hour * 24 * 7, // 7 days
		},
		Server: ServerConfig{
			Port: getEnv("SERVER_PORT"),
		},
	}, nil
}

func getEnv(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return ""
}

// func getEnvAsInt(key string, defaultValue int) int {
// 	if value := os.Getenv(key); value != "" {
// 		if intValue, err := strconv.Atoi(value); err == nil {
// 			return intValue
// 		}
// 	}
// 	return defaultValue
// }
