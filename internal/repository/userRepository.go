package repository

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/souvikjs01/user-grpc/internal/database"
	"github.com/souvikjs01/user-grpc/internal/models"
)

type UserRepository interface {
	Create(user *models.User) error
	GetByID(id uuid.UUID) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	Update(user *models.User) error
	Delete(id uuid.UUID) error
	List(filter models.ListUsersFilter) (*models.ListUsersResponse, error)
	UpdateLastLogin(userID uuid.UUID) error
	UpdatePassword(userID uuid.UUID, hashedPassword string) error
	UpdateRole(userID uuid.UUID, role models.Role) error
	UpdateStatus(userID uuid.UUID, status models.UserStatus) error

	// Refresh token methods
	CreateRefreshToken(token *models.RefreshToken) error
	GetRefreshToken(tokenHash string) (*models.RefreshToken, error)
	RevokeRefreshToken(tokenHash string) error
	RevokeAllUserTokens(userID uuid.UUID) error
	CleanupExpiredTokens() error
}

type userRepository struct {
	db *database.DB
}

func NewUserRepository(db *database.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) Create(user *models.User) error {
	query := `
		INSERT INTO users (id, email, username, password_hash, first_name, last_name, role, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at`

	user.ID = uuid.New()

	return r.db.QueryRow(
		query,
		user.ID,
		user.Email,
		user.Username,
		user.Password,
		user.FirstName,
		user.LastName,
		user.Role,
		user.Status,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
}

func (r *userRepository) GetByID(id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, email, username, password_hash, first_name, last_name, role, status,
			   created_at, updated_at, last_login
		FROM users WHERE id = $1`

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.Role,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	query := `
		SELECT id, email, username, password_hash, first_name, last_name, role, status,
			   created_at, updated_at, last_login
		FROM users WHERE email = $1`

	user := &models.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.Role,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) GetByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, email, username, password_hash, first_name, last_name, role, status,
			   created_at, updated_at, last_login
		FROM users WHERE username = $1`

	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.FirstName,
		&user.LastName,
		&user.Role,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) Update(user *models.User) error {
	query := `
		UPDATE users 
		SET first_name = $2, last_name = $3, username = $4, updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at`

	return r.db.QueryRow(query, user.ID, user.FirstName, user.LastName, user.Username).Scan(&user.UpdatedAt)
}

func (r *userRepository) Delete(id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	result, err := r.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (r *userRepository) List(filter models.ListUsersFilter) (*models.ListUsersResponse, error) {
	// Build WHERE conditions
	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(email ILIKE $%d OR username ILIKE $%d OR first_name ILIKE $%d OR last_name ILIKE $%d)", argIndex, argIndex, argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	if filter.RoleFilter != nil {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argIndex))
		args = append(args, *filter.RoleFilter)
		argIndex++
	}

	if filter.StatusFilter != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, *filter.StatusFilter)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total records
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", whereClause)
	var totalCount int
	err := r.db.QueryRow(countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, err
	}

	// Get paginated results
	offset := (filter.Page - 1) * filter.PageSize
	query := fmt.Sprintf(`
		SELECT id, email, username, first_name, last_name, role, status,
			   created_at, updated_at, last_login
		FROM users %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIndex, argIndex+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.FirstName,
			&user.LastName,
			&user.Role,
			&user.Status,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.LastLogin,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return &models.ListUsersResponse{
		Users:      users,
		TotalCount: totalCount,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
	}, nil
}

func (r *userRepository) UpdateLastLogin(userID uuid.UUID) error {
	query := `UPDATE users SET last_login = NOW() WHERE id = $1`
	_, err := r.db.Exec(query, userID)
	return err
}

func (r *userRepository) UpdatePassword(userID uuid.UUID, hashedPassword string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(query, hashedPassword, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (r *userRepository) UpdateRole(userID uuid.UUID, role models.Role) error {
	query := `UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(query, role, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (r *userRepository) UpdateStatus(userID uuid.UUID, status models.UserStatus) error {
	query := `UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(query, status, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("failed")
	}
	return nil
}

func (r *userRepository) CreateRefreshToken(token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, is_revoked)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at`

	token.ID = uuid.New()

	return r.db.QueryRow(
		query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
		token.IsRevoked,
	).Scan(&token.CreatedAt)
}

func (r *userRepository) GetRefreshToken(tokenHash string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE token_hash = $1 AND is_revoked = false AND expires_at > NOW()`

	token := &models.RefreshToken{}
	err := r.db.QueryRow(query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.IsRevoked,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token not found or expired")
	}
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r *userRepository) RevokeRefreshToken(tokenHash string) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = $1`

	result, err := r.db.Exec(query, tokenHash)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

func (r *userRepository) RevokeAllUserTokens(userID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1 AND is_revoked = false`

	_, err := r.db.Exec(query, userID)
	return err
}

func (r *userRepository) CleanupExpiredTokens() error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW() - INTERVAL '30 days'`

	_, err := r.db.Exec(query)
	return err
}
