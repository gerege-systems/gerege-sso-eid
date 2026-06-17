package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"xyp.gerege.mn/api/internal/store"
)

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.statusCode = code
	sw.ResponseWriter.WriteHeader(code)
}

func Audit(db *store.Postgres) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Read request body for audit (limit to 4KB)
			var reqBody []byte
			if r.Body != nil {
				limited := io.LimitReader(r.Body, 4096)
				reqBody, _ = io.ReadAll(limited)
				r.Body = io.NopCloser(bytes.NewReader(reqBody))
			}

			sw := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(sw, r)

			latency := time.Since(start).Milliseconds()
			clientID, _ := r.Context().Value(ClientIDKey).(string)
			ip := r.Header.Get("X-Real-IP")
			if ip == "" {
				ip = r.RemoteAddr
			}

			entry := store.AuditEntry{
				ClientID:     clientID,
				Endpoint:     r.URL.Path,
				RequestBody:  reqBody,
				ResponseCode: sw.statusCode,
				LatencyMs:    int(latency),
				IPAddress:    ip,
				AuthVia:      sw.Header().Get("X-Auth-Via"),
			}

			// Async insert — background context since request ctx may cancel
			go func() {
				if err := db.InsertAudit(context.Background(), entry); err != nil {
					slog.Error("audit insert failed", "error", err)
				}
			}()
		})
	}
}
