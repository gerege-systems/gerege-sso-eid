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

const (
	// maxRequestBody bounds how much of a request body we buffer in memory.
	// Fingerprint BMP payloads can be a few hundred KB, so keep this generous.
	maxRequestBody = 2 << 20 // 2 MB
	// maxAuditBody caps how many bytes of the request body get persisted to
	// the audit log; the full body still reaches the handler.
	maxAuditBody = 4096 // 4 KB
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

			// Read the full request body so the downstream handler sees the
			// complete payload (fingerprint BMPs can be well over 4KB). Cap at
			// maxRequestBody to bound memory, then hand the full body back.
			var reqBody []byte
			if r.Body != nil {
				limited := io.LimitReader(r.Body, maxRequestBody)
				reqBody, _ = io.ReadAll(limited)
				r.Body = io.NopCloser(bytes.NewReader(reqBody))
			}

			// Persist only the first maxAuditBody bytes to the audit log to
			// avoid storing huge request bodies in the database.
			auditBody := reqBody
			if len(auditBody) > maxAuditBody {
				auditBody = auditBody[:maxAuditBody]
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
				RequestBody:  auditBody,
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
