package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/AbdullahTarar/helm-guard-be/internal/config"
	"helm-scanner/internal/server"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Start server
	log.Printf("Starting server on %s", cfg.Server.Address)
	if err := http.ListenAndServe(cfg.Server.Address, srv); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}