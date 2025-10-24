package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	pb "github.com/souvikjs01/user-grpc/api/proto/user-service"
	"github.com/souvikjs01/user-grpc/internal/models"
	"github.com/souvikjs01/user-grpc/internal/service"
)

type UserHandler struct {
	pb.UnimplementedUserServiceServer
	userService service.UserService
}

func NewUserHandler(userService service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// Authentication methods
func (h *UserHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Convert protobuf request to service model
	serviceReq := &models.CreateUserRequest{
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	user, tokens, err := h.userService.Register(serviceReq)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "registration failed: %v", err)
	}

	return &pb.RegisterResponse{
		User:         h.userModelToProto(user),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (h *UserHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	serviceReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	user, tokens, err := h.userService.Login(serviceReq)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "login failed: %v", err)
	}

	return &pb.LoginResponse{
		User:         h.userModelToProto(user),
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (h *UserHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	tokens, err := h.userService.RefreshToken(req.RefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "token refresh failed: %v", err)
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (h *UserHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*emptypb.Empty, error) {
	err := h.userService.Logout(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "logout failed: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// Profile management methods
func (h *UserHandler) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.GetProfileResponse, error) {
	user, err := h.userService.GetProfile(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to get profile: %v", err)
	}

	return &pb.GetProfileResponse{
		User: h.userModelToProto(user),
	}, nil
}

func (h *UserHandler) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UpdateProfileResponse, error) {
	serviceReq := &models.UpdateUserRequest{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Username:  req.Username,
	}

	user, err := h.userService.UpdateProfile(req.Token, serviceReq)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to update profile: %v", err)
	}

	return &pb.UpdateProfileResponse{
		User: h.userModelToProto(user),
	}, nil
}

func (h *UserHandler) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*emptypb.Empty, error) {
	serviceReq := &models.ChangePasswordRequest{
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}

	err := h.userService.ChangePassword(req.Token, serviceReq)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to change password: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (h *UserHandler) DeleteProfile(ctx context.Context, req *pb.DeleteProfileRequest) (*emptypb.Empty, error) {
	err := h.userService.DeleteProfile(req.Token, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to delete profile: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// Admin methods
func (h *UserHandler) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	filter := models.ListUsersFilter{
		Page:     int(req.Page),
		PageSize: int(req.PageSize),
		Search:   req.Search,
	}

	// Convert role filter if provided
	if req.RoleFilter != pb.Role_ROLE_UNSPECIFIED {
		role := h.protoRoleToModel(req.RoleFilter)
		filter.RoleFilter = &role
	}

	// Convert status filter if provided
	if req.StatusFilter != pb.UserStatus_STATUS_UNSPECIFIED {
		status := h.protoStatusToModel(req.StatusFilter)
		filter.StatusFilter = &status
	}

	response, err := h.userService.ListUsers(req.Token, filter)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "failed to list users: %v", err)
	}

	// Convert users to proto
	var protoUsers []*pb.User
	for _, user := range response.Users {
		protoUsers = append(protoUsers, h.userModelToProto(user))
	}

	return &pb.ListUsersResponse{
		Users:      protoUsers,
		TotalCount: int32(response.TotalCount),
		Page:       int32(response.Page),
		PageSize:   int32(response.PageSize),
	}, nil
}

func (h *UserHandler) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID: %v", err)
	}

	user, err := h.userService.GetUser(req.Token, userID)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "failed to get user: %v", err)
	}

	return &pb.GetUserResponse{
		User: h.userModelToProto(user),
	}, nil
}

func (h *UserHandler) UpdateUserRole(ctx context.Context, req *pb.UpdateUserRoleRequest) (*emptypb.Empty, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID: %v", err)
	}

	role := h.protoRoleToModel(req.Role)
	err = h.userService.UpdateUserRole(req.Token, userID, role)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "failed to update user role: %v", err)
	}

	return &emptypb.Empty{}, nil
}

func (h *UserHandler) DeactivateUser(ctx context.Context, req *pb.DeactivateUserRequest) (*emptypb.Empty, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID: %v", err)
	}

	err = h.userService.DeactivateUser(req.Token, userID)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "failed to deactivate user: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// Helper methods for converting between models and protobuf
func (h *UserHandler) userModelToProto(user *models.User) *pb.User {
	var lastLogin *timestamppb.Timestamp
	if user.LastLogin != nil {
		lastLogin = timestamppb.New(*user.LastLogin)
	}

	return &pb.User{
		Id:        user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      h.modelRoleToProto(user.Role),
		Status:    h.modelStatusToProto(user.Status),
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
		LastLogin: lastLogin,
	}
}

func (h *UserHandler) modelRoleToProto(role models.Role) pb.Role {
	switch role {
	case models.RoleUser:
		return pb.Role_ROLE_USER
	case models.RoleAdmin:
		return pb.Role_ROLE_ADMIN
	case models.RoleModerator:
		return pb.Role_ROLE_MODERATOR
	default:
		return pb.Role_ROLE_UNSPECIFIED
	}
}

func (h *UserHandler) protoRoleToModel(role pb.Role) models.Role {
	switch role {
	case pb.Role_ROLE_USER:
		return models.RoleUser
	case pb.Role_ROLE_ADMIN:
		return models.RoleAdmin
	case pb.Role_ROLE_MODERATOR:
		return models.RoleModerator
	default:
		return models.RoleUser
	}
}

func (h *UserHandler) modelStatusToProto(status models.UserStatus) pb.UserStatus {
	switch status {
	case models.StatusActive:
		return pb.UserStatus_STATUS_ACTIVE
	case models.StatusInactive:
		return pb.UserStatus_STATUS_INACTIVE
	case models.StatusSuspended:
		return pb.UserStatus_STATUS_SUSPENDED
	default:
		return pb.UserStatus_STATUS_UNSPECIFIED
	}
}

func (h *UserHandler) protoStatusToModel(status pb.UserStatus) models.UserStatus {
	switch status {
	case pb.UserStatus_STATUS_ACTIVE:
		return models.StatusActive
	case pb.UserStatus_STATUS_INACTIVE:
		return models.StatusInactive
	case pb.UserStatus_STATUS_SUSPENDED:
		return models.StatusSuspended
	default:
		return models.StatusActive
	}
}
