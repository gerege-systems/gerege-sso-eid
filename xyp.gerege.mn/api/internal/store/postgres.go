package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type VerifyClient struct {
	ID           string    `json:"id"`
	SecretHash   string    `json:"-"`
	Name         string    `json:"name"`
	ContactEmail string    `json:"contact_email,omitempty"`
	Scopes       []string  `json:"scopes"`
	RateLimit    int       `json:"rate_limit"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AuditEntry struct {
	ID           int64     `json:"id"`
	ClientID     string    `json:"client_id"`
	Endpoint     string    `json:"endpoint"`
	RequestBody  []byte    `json:"request_body,omitempty"`
	ResponseCode int       `json:"response_code"`
	LatencyMs    int       `json:"latency_ms"`
	IPAddress    string    `json:"ip_address"`
	AuthVia      string    `json:"auth_via,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type UsageStat struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Endpoint   string `json:"endpoint"`
	TotalCalls int    `json:"total_calls"`
}

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store.NewPostgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("store.NewPostgres ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) Migrate(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS verify_clients (
			id            TEXT PRIMARY KEY,
			secret_hash   TEXT NOT NULL,
			name          TEXT NOT NULL,
			contact_email TEXT,
			scopes        TEXT[] NOT NULL DEFAULT '{citizen.lookup,citizen.verify,org.lookup,org.verify}',
			rate_limit    INTEGER NOT NULL DEFAULT 100,
			active        BOOLEAN NOT NULL DEFAULT true,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_verify_clients_active ON verify_clients(active);

		CREATE TABLE IF NOT EXISTS verify_audit_log (
			id            BIGSERIAL PRIMARY KEY,
			client_id     TEXT NOT NULL,
			endpoint      TEXT NOT NULL,
			request_body  JSONB,
			response_code INTEGER NOT NULL,
			latency_ms    INTEGER,
			ip_address    TEXT,
			auth_via      TEXT,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		ALTER TABLE verify_audit_log ADD COLUMN IF NOT EXISTS auth_via TEXT;
		CREATE INDEX IF NOT EXISTS idx_verify_audit_client ON verify_audit_log(client_id);
		CREATE INDEX IF NOT EXISTS idx_verify_audit_created ON verify_audit_log(created_at);
	`)
	return err
}

// --- Client CRUD ---

func (p *Postgres) GetClient(ctx context.Context, clientID string) (*VerifyClient, error) {
	var c VerifyClient
	err := p.pool.QueryRow(ctx,
		`SELECT id, secret_hash, name, contact_email, scopes, rate_limit, active, created_at, updated_at
		 FROM verify_clients WHERE id = $1`, clientID,
	).Scan(&c.ID, &c.SecretHash, &c.Name, &c.ContactEmail, &c.Scopes, &c.RateLimit, &c.Active, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("store.GetClient: %w", err)
	}
	return &c, nil
}

func (p *Postgres) ListClients(ctx context.Context) ([]VerifyClient, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, contact_email, scopes, rate_limit, active, created_at, updated_at
		 FROM verify_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListClients: %w", err)
	}
	defer rows.Close()

	var clients []VerifyClient
	for rows.Next() {
		var c VerifyClient
		if err := rows.Scan(&c.ID, &c.Name, &c.ContactEmail, &c.Scopes, &c.RateLimit, &c.Active, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store.ListClients scan: %w", err)
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (p *Postgres) CreateClient(ctx context.Context, name, contactEmail string) (*VerifyClient, string, error) {
	clientID := fmt.Sprintf("vfy_%x", mustRandBytes(16))
	clientSecret := base64.RawURLEncoding.EncodeToString(mustRandBytes(32))

	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), 12)
	if err != nil {
		return nil, "", fmt.Errorf("store.CreateClient bcrypt: %w", err)
	}

	_, err = p.pool.Exec(ctx,
		`INSERT INTO verify_clients (id, secret_hash, name, contact_email)
		 VALUES ($1, $2, $3, $4)`, clientID, string(hash), name, contactEmail)
	if err != nil {
		return nil, "", fmt.Errorf("store.CreateClient: %w", err)
	}

	c := &VerifyClient{
		ID:           clientID,
		Name:         name,
		ContactEmail: contactEmail,
		Scopes:       []string{"citizen.lookup", "citizen.verify", "org.lookup", "org.verify"},
		RateLimit:    100,
		Active:       true,
	}
	return c, clientSecret, nil
}

func (p *Postgres) DeactivateClient(ctx context.Context, clientID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE verify_clients SET active = false, updated_at = now() WHERE id = $1`, clientID)
	if err != nil {
		return fmt.Errorf("store.DeactivateClient: %w", err)
	}
	return nil
}

// --- Audit Log ---

func (p *Postgres) InsertAudit(ctx context.Context, entry AuditEntry) error {
	var via any
	if entry.AuthVia != "" {
		via = entry.AuthVia
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO verify_audit_log (client_id, endpoint, request_body, response_code, latency_ms, ip_address, auth_via)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.ClientID, entry.Endpoint, entry.RequestBody, entry.ResponseCode, entry.LatencyMs, entry.IPAddress, via)
	if err != nil {
		return fmt.Errorf("store.InsertAudit: %w", err)
	}
	return nil
}

func (p *Postgres) GetUsage(ctx context.Context, clientID, from, to string) ([]UsageStat, error) {
	query := `
		SELECT al.client_id, COALESCE(c.name, al.client_id), al.endpoint, COUNT(*) as total_calls
		FROM verify_audit_log al
		LEFT JOIN verify_clients c ON c.id = al.client_id
		WHERE 1=1`
	args := []any{}
	argIdx := 1

	if clientID != "" {
		query += fmt.Sprintf(" AND al.client_id = $%d", argIdx)
		args = append(args, clientID)
		argIdx++
	}
	if from != "" {
		query += fmt.Sprintf(" AND al.created_at >= $%d", argIdx)
		args = append(args, from)
		argIdx++
	}
	if to != "" {
		query += fmt.Sprintf(" AND al.created_at <= $%d", argIdx)
		args = append(args, to)
		argIdx++
	}

	query += " GROUP BY al.client_id, c.name, al.endpoint ORDER BY total_calls DESC"

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.GetUsage: %w", err)
	}
	defer rows.Close()

	var stats []UsageStat
	for rows.Next() {
		var s UsageStat
		if err := rows.Scan(&s.ClientID, &s.ClientName, &s.Endpoint, &s.TotalCalls); err != nil {
			return nil, fmt.Errorf("store.GetUsage scan: %w", err)
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

func mustRandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}
