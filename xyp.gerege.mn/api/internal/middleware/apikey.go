package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"xyp.gerege.mn/api/internal/store"
)

type contextKey string

const ClientIDKey contextKey = "client_id"
const ClientRateLimitKey contextKey = "client_rate_limit"

func APIKeyAuth(db *store.Postgres, rdb *store.Redis) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientID, clientSecret, ok := r.BasicAuth()
			if !ok || clientID == "" || clientSecret == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="xyp.gerege.mn"`)
				jsonError(w, http.StatusUnauthorized, "missing credentials")
				return
			}

			client, err := db.GetClient(r.Context(), clientID)
			if err != nil {
				slog.Error("apikey auth db error", "error", err)
				jsonError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if client == nil {
				// Constant-time comparison to avoid timing leaks on client existence
				bcrypt.CompareHashAndPassword([]byte("$2a$12$000000000000000000000u"), []byte(clientSecret))
				jsonError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			if !client.Active {
				jsonError(w, http.StatusForbidden, "client deactivated")
				return
			}

			if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)); err != nil {
				jsonError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}

			// Scope check
			endpoint := scopeFromPath(r.URL.Path)
			if !hasScope(client.Scopes, endpoint) {
				jsonError(w, http.StatusForbidden, "insufficient scope")
				return
			}

			ctx := context.WithValue(r.Context(), ClientIDKey, client.ID)
			ctx = context.WithValue(ctx, ClientRateLimitKey, client.RateLimit)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AdminAuth(adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if len(token) < 8 || token[:7] != "Bearer " {
				jsonError(w, http.StatusUnauthorized, "missing admin key")
				return
			}
			provided := token[7:]
			if subtle.ConstantTimeCompare([]byte(provided), []byte(adminKey)) != 1 {
				jsonError(w, http.StatusUnauthorized, "invalid admin key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func scopeFromPath(path string) string {
	switch path {
	case "/v1/citizen/lookup":
		return "citizen.lookup"
	case "/v1/citizen/verify":
		return "citizen.verify"
	case "/v1/org/lookup":
		return "org.lookup"
	case "/v1/org/verify":
		return "org.verify"
	case "/v1/citizen/authenticate":
		return "citizen.verify"
	case "/v1/org/authenticate":
		return "org.verify"
	case "/v1/citizen/finger":
		return "citizen.verify"
	default:
		return ""
	}
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
