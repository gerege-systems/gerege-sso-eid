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

type DANClient struct {
	ID           string    `json:"id"`
	SecretHash   string    `json:"-"`
	HMACKey      string    `json:"-"`
	Name         string    `json:"name"`
	CallbackURLs []string  `json:"callback_urls"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
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

// Migrate creates the dan_clients table if it doesn't exist.
func (p *Postgres) Migrate(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS dan_clients (
			id            TEXT PRIMARY KEY,
			secret_hash   TEXT NOT NULL,
			hmac_key      TEXT NOT NULL DEFAULT '',
			name          TEXT NOT NULL,
			callback_urls TEXT[] NOT NULL DEFAULT '{}',
			active        BOOLEAN NOT NULL DEFAULT true,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_dan_clients_active ON dan_clients(active);
	`)
	return err
}

func (p *Postgres) GetDANClient(ctx context.Context, clientID string) (*DANClient, error) {
	var c DANClient
	err := p.pool.QueryRow(ctx,
		`SELECT id, secret_hash, hmac_key, name, callback_urls, active
		 FROM dan_clients WHERE id = $1`, clientID,
	).Scan(&c.ID, &c.SecretHash, &c.HMACKey, &c.Name, &c.CallbackURLs, &c.Active)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("store.GetDANClient: %w", err)
	}
	return &c, nil
}

func (p *Postgres) ListDANClients(ctx context.Context) ([]DANClient, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, name, callback_urls, active, created_at, updated_at
		 FROM dan_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.ListDANClients: %w", err)
	}
	defer rows.Close()

	var clients []DANClient
	for rows.Next() {
		var c DANClient
		if err := rows.Scan(&c.ID, &c.Name, &c.CallbackURLs, &c.Active, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store.ListDANClients scan: %w", err)
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (p *Postgres) CreateDANClient(ctx context.Context, name string, callbackURLs []string) (*DANClient, string, string, error) {
	clientID := fmt.Sprintf("dan_%x", mustRandBytes(16))
	clientSecret := base64.RawURLEncoding.EncodeToString(mustRandBytes(32))
	hmacKey := base64.RawURLEncoding.EncodeToString(mustRandBytes(32))

	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), 12)
	if err != nil {
		return nil, "", "", fmt.Errorf("store.CreateDANClient bcrypt: %w", err)
	}

	_, err = p.pool.Exec(ctx,
		`INSERT INTO dan_clients (id, secret_hash, hmac_key, name, callback_urls)
		 VALUES ($1, $2, $3, $4, $5)`, clientID, string(hash), hmacKey, name, callbackURLs)
	if err != nil {
		return nil, "", "", fmt.Errorf("store.CreateDANClient: %w", err)
	}

	c := &DANClient{
		ID:           clientID,
		Name:         name,
		CallbackURLs: callbackURLs,
		Active:       true,
	}
	return c, clientSecret, hmacKey, nil
}

// RegenerateDANClientSecret issues a fresh secret for an existing client,
// replaces the stored bcrypt hash, and returns the new plaintext secret once.
// Returns ("", nil) if no client with the given id exists.
func (p *Postgres) RegenerateDANClientSecret(ctx context.Context, clientID string) (string, error) {
	clientSecret := base64.RawURLEncoding.EncodeToString(mustRandBytes(32))

	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), 12)
	if err != nil {
		return "", fmt.Errorf("store.RegenerateDANClientSecret bcrypt: %w", err)
	}

	tag, err := p.pool.Exec(ctx,
		`UPDATE dan_clients SET secret_hash = $1, updated_at = now() WHERE id = $2`,
		string(hash), clientID)
	if err != nil {
		return "", fmt.Errorf("store.RegenerateDANClientSecret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", nil
	}
	return clientSecret, nil
}

func (p *Postgres) DeactivateDANClient(ctx context.Context, clientID string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE dan_clients SET active = false, updated_at = now() WHERE id = $1`, clientID)
	if err != nil {
		return fmt.Errorf("store.DeactivateDANClient: %w", err)
	}
	return nil
}

func mustRandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}
