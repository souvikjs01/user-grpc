package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/souvikjs01/user-grpc/internal/config"
	"github.com/souvikjs01/user-grpc/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type JWTService interface {
	GenerateTokenPair(user *models.User) (*models.TokenPair, error)
	ValidateAccessToken(tokenString string) (*models.JWTClaims, error)
	RefreshAccessToken(refreshTokenString string) (*models.TokenPair, error)
	HashPassword(password string) (string, error)
	ValidatePassword(password, hashedPassword string) error
	HashRefreshToken(token string) string
}

type jwtService struct {
	config     *config.JWTConfig
	repository UserTokenRepository
}

type UserTokenRepository interface {
	GetRefreshToken(tokenHash string) (*models.RefreshToken, error)
	CreateRefreshToken(token *models.RefreshToken) error
	RevokeRefreshToken(tokenHash string) error
	GetByID(id uuid.UUID) (*models.User, error)
}

type CustomClaims struct {
	UserID   string      `json:"user_id"`
	Email    string      `json:"email"`
	Username string      `json:"username"`
	Role     models.Role `json:"role"`
	jwt.RegisteredClaims
}

func NewJWTService(config *config.JWTConfig, repo UserTokenRepository) JWTService {
	return &jwtService{
		config:     config,
		repository: repo,
	}
}

func (s *jwtService) GenerateTokenPair(user *models.User) (*models.TokenPair, error) {
	// Generate access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *jwtService) generateAccessToken(user *models.User) (string, error) {
	claims := CustomClaims{
		UserID:   user.ID.String(),
		Email:    user.Email,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "user-service",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.Secret))
}

func (s *jwtService) generateRefreshToken(user *models.User) (string, error) {
	// Generate a random refresh token
	refreshTokenID := uuid.New().String()

	claims := jwt.RegisteredClaims{
		ID:        refreshTokenID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.RefreshTokenExpiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "user-service",
		Subject:   user.ID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", err
	}

	// Store refresh token in database
	refreshTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: s.HashRefreshToken(tokenString),
		ExpiresAt: time.Now().Add(s.config.RefreshTokenExpiry),
	}

	err = s.repository.CreateRefreshToken(refreshTokenModel)
	if err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return tokenString, nil
}

func (s *jwtService) ValidateAccessToken(tokenString string) (*models.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return &models.JWTClaims{
		UserID:   claims.UserID,
		Email:    claims.Email,
		Username: claims.Username,
		Role:     claims.Role,
	}, nil
}

func (s *jwtService) RefreshAccessToken(refreshTokenString string) (*models.TokenPair, error) {
	// Parse refresh token
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("refresh token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify refresh token exists in database
	tokenHash := s.HashRefreshToken(refreshTokenString)
	storedToken, err := s.repository.GetRefreshToken(tokenHash)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", err)
	}

	// Get user
	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	user, err := s.repository.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Revoke old refresh token
	err = s.repository.RevokeRefreshToken(storedToken.TokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// Generate new token pair
	return s.GenerateTokenPair(user)
}

func (s *jwtService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (s *jwtService) ValidatePassword(password, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (s *jwtService) HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
