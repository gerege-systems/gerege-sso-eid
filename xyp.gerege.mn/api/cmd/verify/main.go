package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xyp.gerege.mn/api/internal/handler"
	"xyp.gerege.mn/api/internal/middleware"
	"xyp.gerege.mn/api/internal/provider"
	"xyp.gerege.mn/api/internal/store"
)

func main() {
	slog.Info("starting xyp.gerege.mn api")

	port := envOrDefault("PORT", "8446")
	databaseURL := envOrDefault("VERIFY_DATABASE_URL", "")
	redisURL := envOrDefault("VERIFY_REDIS_URL", "")
	adminKey := envOrDefault("VERIFY_ADMIN_KEY", "")
	allowedOrigin := envOrDefault("VERIFY_CORS_ORIGIN", "https://xyp.gerege.mn")

	upstreamURL := envOrDefault("UPSTREAM_API_URL", "")
	upstreamKey := envOrDefault("UPSTREAM_API_KEY", "")

	// eSign fingerprint service lives on a separate host from the main upstream.
	esignURL := envOrDefault("ESIGN_API_URL", "http://10.0.0.63:8003")
	esignKey := envOrDefault("ESIGN_API_KEY", "")

	if databaseURL == "" {
		slog.Error("VERIFY_DATABASE_URL is required")
		os.Exit(1)
	}
	if adminKey == "" {
		slog.Error("VERIFY_ADMIN_KEY is required")
		os.Exit(1)
	}

	ctx := context.Background()

	// Database
	db, err := store.NewPostgres(ctx, databaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("connected to database")

	if err := db.Migrate(ctx); err != nil {
		slog.Warn("migration error", "error", err)
	}

	// Redis
	var rdb *store.Redis
	if redisURL != "" {
		rdb, err = store.NewRedis(redisURL)
		if err != nil {
			slog.Error("failed to connect to redis", "error", err)
			os.Exit(1)
		}
		defer rdb.Close()
		if err := rdb.Ping(ctx); err != nil {
			slog.Error("redis ping failed", "error", err)
			os.Exit(1)
		}
		slog.Info("connected to redis")
	} else {
		slog.Warn("VERIFY_REDIS_URL not set, rate limiting disabled")
	}

	// Providers (both use the same upstream API at 10.0.0.187:8000)
	citizenProv := provider.NewCitizenHTTP(upstreamURL, upstreamKey)
	orgProv := provider.NewOrgHTTP(upstreamURL, upstreamKey)
	fingerProv := provider.NewEsignHTTP(esignURL, esignKey)

	// Handler
	h := handler.New(handler.Config{
		DB:       db,
		Redis:    rdb,
		AdminKey: adminKey,
		Citizen:  citizenProv,
		Org:      orgProv,
		Finger:   fingerProv,
	})

	// Middleware
	apiKeyAuth := middleware.APIKeyAuth(db, rdb)
	adminAuth := middleware.AdminAuth(adminKey)
	rateLimiter := middleware.RateLimit(rdb)
	auditor := middleware.Audit(db)

	// Router
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.Health)

	// Verification API: apikey auth → rate limit → audit → handler
	mux.Handle("POST /v1/citizen/lookup", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.CitizenLookup)))))
	mux.Handle("POST /v1/citizen/verify", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.CitizenVerify)))))
	mux.Handle("POST /v1/org/lookup", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.OrgLookup)))))
	mux.Handle("POST /v1/org/verify", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.OrgVerify)))))
	mux.Handle("POST /v1/citizen/finger", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.CitizenFinger)))))

	// Authenticate API: apikey auth → rate limit → audit → handler
	mux.Handle("POST /v1/citizen/authenticate", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.AuthenticateCitizen)))))
	mux.Handle("POST /v1/org/authenticate", apiKeyAuth(rateLimiter(auditor(http.HandlerFunc(h.AuthenticateOrg)))))

	// Admin API: admin key auth
	mux.Handle("GET /api/clients", adminAuth(http.HandlerFunc(h.ListClients)))
	mux.Handle("POST /api/clients", adminAuth(http.HandlerFunc(h.CreateClient)))
	mux.Handle("DELETE /api/clients/{id}", adminAuth(http.HandlerFunc(h.DeactivateClient)))
	mux.Handle("GET /api/usage", adminAuth(http.HandlerFunc(h.Usage)))

	// Global middleware
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
