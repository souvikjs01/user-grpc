package service

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/souvikjs01/user-grpc/internal/auth"
	"github.com/souvikjs01/user-grpc/internal/models"
	"github.com/souvikjs01/user-grpc/internal/repository"
)

type UserService interface {
	// Authentication
	Register(req *models.CreateUserRequest) (*models.User, *models.TokenPair, error)
	Login(req *models.LoginRequest) (*models.User, *models.TokenPair, error)
	RefreshToken(refreshToken string) (*models.TokenPair, error)
	Logout(token string) error

	// Profile management
	GetProfile(token string) (*models.User, error)
	UpdateProfile(token string, req *models.UpdateUserRequest) (*models.User, error)
	ChangePassword(token string, req *models.ChangePasswordRequest) error
	DeleteProfile(token, password string) error

	// User management (admin)
	ListUsers(token string, filter models.ListUsersFilter) (*models.ListUsersResponse, error)
	GetUser(token string, userID uuid.UUID) (*models.User, error)
	UpdateUserRole(token string, userID uuid.UUID, role models.Role) error
	DeactivateUser(token string, userID uuid.UUID) error
}

type userService struct {
	userRepo   repository.UserRepository
	jwtService auth.JWTService
}

func NewUserService(userRepo repository.UserRepository, jwtService auth.JWTService) UserService {
	return &userService{
		userRepo:   userRepo,
		jwtService: jwtService,
	}
}

// Authentication methods
func (s *userService) Register(req *models.CreateUserRequest) (*models.User, *models.TokenPair, error) {
	// Validate input
	if err := s.validateCreateUserRequest(req); err != nil {
		return nil, nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if user already exists
	if _, err := s.userRepo.GetByEmail(req.Email); err == nil {
		return nil, nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	if _, err := s.userRepo.GetByUsername(req.Username); err == nil {
		return nil, nil, fmt.Errorf("user with username %s already exists", req.Username)
	}

	// Hash password
	hashedPassword, err := s.jwtService.HashPassword(req.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Email:     strings.ToLower(req.Email),
		Username:  req.Username,
		Password:  hashedPassword,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Role:      models.RoleUser,
		Status:    models.StatusActive,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate tokens
	tokens, err := s.jwtService.GenerateTokenPair(user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(user.ID); err != nil {
		// Log error but don't fail the registration
		fmt.Printf("failed to update last login: %v\n", err)
	}

	return user, tokens, nil
}

func (s *userService) Login(req *models.LoginRequest) (*models.User, *models.TokenPair, error) {
	// Validate input
	if req.Email == "" || req.Password == "" {
		return nil, nil, fmt.Errorf("email and password are required")
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(strings.ToLower(req.Email))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if user.Status != models.StatusActive {
		return nil, nil, fmt.Errorf("user account is not active")
	}

	// Validate password
	if err := s.jwtService.ValidatePassword(req.Password, user.Password); err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	tokens, err := s.jwtService.GenerateTokenPair(user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(user.ID); err != nil {
		fmt.Printf("failed to update last login: %v\n", err)
	}

	return user, tokens, nil
}

func (s *userService) RefreshToken(refreshToken string) (*models.TokenPair, error) {
	return s.jwtService.RefreshAccessToken(refreshToken)
}

func (s *userService) Logout(token string) error {
	// For a complete logout, we would need to blacklist the access token
	// For now, we'll just revoke all refresh tokens for the user
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	return s.userRepo.RevokeAllUserTokens(userID)
}

// Profile management methods
func (s *userService) GetProfile(token string) (*models.User, error) {
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Clear password for response
	user.Password = ""
	return user, nil
}

func (s *userService) UpdateProfile(token string, req *models.UpdateUserRequest) (*models.User, error) {
	// Validate token
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Validate input
	if err := s.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Get current user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if username is taken by another user
	if req.Username != user.Username {
		if existingUser, err := s.userRepo.GetByUsername(req.Username); err == nil && existingUser.ID != userID {
			return nil, fmt.Errorf("username %s is already taken", req.Username)
		}
	}

	// Update user fields
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Username = req.Username

	if err := s.userRepo.Update(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Clear password for response
	user.Password = ""
	return user, nil
}

func (s *userService) ChangePassword(token string, req *models.ChangePasswordRequest) error {
	// Validate token
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// Validate input
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return fmt.Errorf("current password and new password are required")
	}

	if len(req.NewPassword) < 6 {
		return fmt.Errorf("new password must be at least 6 characters long")
	}

	// Get current user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Validate current password
	if err := s.jwtService.ValidatePassword(req.CurrentPassword, user.Password); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := s.jwtService.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(userID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all refresh tokens to force re-login
	if err := s.userRepo.RevokeAllUserTokens(userID); err != nil {
		fmt.Printf("failed to revoke refresh tokens: %v\n", err)
	}

	return nil
}

func (s *userService) DeleteProfile(token, password string) error {
	// Validate token
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// Get current user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Validate password
	if err := s.jwtService.ValidatePassword(password, user.Password); err != nil {
		return fmt.Errorf("password is incorrect")
	}

	// Delete user
	return s.userRepo.Delete(userID)
}

// Admin methods
func (s *userService) ListUsers(token string, filter models.ListUsersFilter) (*models.ListUsersResponse, error) {
	// Validate token and check admin role
	if err := s.requireAdminRole(token); err != nil {
		return nil, err
	}

	// Set default pagination
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 || filter.PageSize > 100 {
		filter.PageSize = 20
	}

	return s.userRepo.List(filter)
}

func (s *userService) GetUser(token string, userID uuid.UUID) (*models.User, error) {
	// Validate token and check admin role
	if err := s.requireAdminRole(token); err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Clear password for response
	user.Password = ""
	return user, nil
}

func (s *userService) UpdateUserRole(token string, userID uuid.UUID, role models.Role) error {
	// Validate token and check admin role
	if err := s.requireAdminRole(token); err != nil {
		return err
	}

	// Validate role
	if role != models.RoleUser && role != models.RoleAdmin && role != models.RoleModerator {
		return fmt.Errorf("invalid role: %s", role)
	}

	return s.userRepo.UpdateRole(userID, role)
}

func (s *userService) DeactivateUser(token string, userID uuid.UUID) error {
	// Validate token and check admin role
	if err := s.requireAdminRole(token); err != nil {
		return err
	}

	// Get current user from token to prevent self-deactivation
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	currentUserID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	if currentUserID == userID {
		return fmt.Errorf("cannot deactivate your own account")
	}

	return s.userRepo.UpdateStatus(userID, models.StatusInactive)
}

// Helper methods
func (s *userService) requireAdminRole(token string) error {
	claims, err := s.jwtService.ValidateAccessToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	if claims.Role != models.RoleAdmin {
		return fmt.Errorf("admin role required")
	}

	return nil
}

func (s *userService) validateCreateUserRequest(req *models.CreateUserRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}

	// Basic email validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return fmt.Errorf("invalid email format")
	}

	if req.Username == "" {
		return fmt.Errorf("username is required")
	}

	if len(req.Username) < 3 || len(req.Username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}

	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	if len(req.Password) < 6 {
		return fmt.Errorf("password must be at least 6 characters long")
	}

	if req.FirstName == "" {
		return fmt.Errorf("first name is required")
	}

	if req.LastName == "" {
		return fmt.Errorf("last name is required")
	}

	return nil
}

func (s *userService) validateUpdateUserRequest(req *models.UpdateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}

	if len(req.Username) < 3 || len(req.Username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}

	if req.FirstName == "" {
		return fmt.Errorf("first name is required")
	}

	if req.LastName == "" {
		return fmt.Errorf("last name is required")
	}

	return nil
}
