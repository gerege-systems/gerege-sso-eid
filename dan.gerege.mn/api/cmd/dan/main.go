package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dan.gerege.mn/api/internal/dan"
	"dan.gerege.mn/api/internal/handler"
	"dan.gerege.mn/api/internal/middleware"
	"dan.gerege.mn/api/internal/store"
)

func main() {
	slog.Info("starting dan.gerege.mn api")

	cfg := dan.Config{
		ClientID:     envOrDefault("DAN_CLIENT_ID", ""),
		ClientSecret: envOrDefault("DAN_CLIENT_SECRET", ""),
		Scope:        envOrDefault("DAN_SCOPE", ""),
		CallbackURI:  envOrDefault("DAN_CALLBACK_URI", "https://dan.gerege.mn/authorized"),
		TokenURL:     envOrDefault("DAN_TOKEN_URL", "https://sso.gov.mn/oauth2/token"),
		ServiceURL:   envOrDefault("DAN_SERVICE_URL", "https://sso.gov.mn/oauth2/api/v1/service"),
	}

	stateSecret := envOrDefault("DAN_STATE_SECRET", "change-me-in-production")
	adminKey := envOrDefault("DAN_ADMIN_KEY", "")
	allowedOrigin := envOrDefault("CORS_ORIGIN", "https://dan.gerege.mn")
	port := envOrDefault("PORT", "8444")
	databaseURL := envOrDefault("DAN_DATABASE_URL", "")

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		slog.Error("DAN_CLIENT_ID and DAN_CLIENT_SECRET are required")
		os.Exit(1)
	}

	if databaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	// Database
	ctx := context.Background()
	db, err := store.NewPostgres(ctx, databaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("connected to database")

	// Auto-migrate
	if err := db.Migrate(ctx); err != nil {
		slog.Warn("migration error", "error", err)
	}

	// Handler
	h := handler.New(handler.Config{
		DAN:           cfg,
		DB:            db,
		StateSecret:   stateSecret,
		AllowedOrigin: allowedOrigin,
		AdminKey:      adminKey,
	})

	// Router
	mux := http.NewServeMux()
	mux.HandleFunc("GET /verify", h.Verify)
	mux.HandleFunc("GET /authorized", h.Authorized)
	mux.HandleFunc("GET /try", h.Try)
	mux.HandleFunc("GET /api/clients", h.ListClients)
	mux.HandleFunc("POST /api/clients", h.CreateClient)
	mux.HandleFunc("POST /api/clients/{id}/secret", h.RegenerateClientSecret)
	mux.HandleFunc("DELETE /api/clients/{id}", h.DeactivateClient)
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /favicon.ico", h.Favicon)
	mux.HandleFunc("GET /", h.Index)

	// Middleware
	var root http.Handler = mux
	root = middleware.Logger(root)
	root = middleware.CORS(allowedOrigin)(root)

	// Server
	addr := ":" + port
	srv := &http.Server{
		Addr:         addr,
		Handler:      root,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
