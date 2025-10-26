package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/souvikjs01/user-grpc/api/proto/user-service"
	"github.com/souvikjs01/user-grpc/internal/auth"
	"github.com/souvikjs01/user-grpc/internal/config"
	"github.com/souvikjs01/user-grpc/internal/database"
	"github.com/souvikjs01/user-grpc/internal/handlers"
	"github.com/souvikjs01/user-grpc/internal/repository"
	"github.com/souvikjs01/user-grpc/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config")
	}

	log.Printf("Starting User Service on port %s", cfg.Server.Port)

	// Connect to database
	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize repository
	userRepo := repository.NewUserRepository(db)

	// Initialize JWT service
	jwtService := auth.NewJWTService(&cfg.JWT, userRepo)

	// Initialize service layer
	userService := service.NewUserService(userRepo, jwtService)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register services
	pb.RegisterUserServiceServer(grpcServer, userHandler)

	// Enable gRPC reflection for development
	reflection.Register(grpcServer)

	// Start listening
	lis, err := net.Listen("tcp", ":"+cfg.Server.Port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", cfg.Server.Port, err)
	}

	// Start cleanup goroutine for expired tokens
	go startTokenCleanup(userRepo)

	// Start server in a goroutine
	go func() {
		log.Printf("gRPC server listening on port %s", cfg.Server.Port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until we receive our signal
	<-c

	// Graceful shutdown
	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
	log.Println("Server stopped")
}

// startTokenCleanup runs a background job to clean up expired refresh tokens
func startTokenCleanup(repo repository.UserRepository) {
	ticker := time.NewTicker(1 * time.Hour) // Run every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := repo.CleanupExpiredTokens(); err != nil {
				log.Printf("Error cleaning up expired tokens: %v", err)
			} else {
				log.Println("Successfully cleaned up expired tokens")
			}
		}
	}
}
