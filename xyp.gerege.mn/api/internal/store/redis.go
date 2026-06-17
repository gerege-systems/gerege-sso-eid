package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	client *redis.Client
}

func NewRedis(redisURL string) (*Redis, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("store.NewRedis: %w", err)
	}
	client := redis.NewClient(opts)
	return &Redis{client: client}, nil
}

func (r *Redis) Close() error {
	return r.client.Close()
}

func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// IncrRateLimit increments the rate limit counter for a client and returns the current count.
// The key expires after 1 minute.
func (r *Redis) IncrRateLimit(ctx context.Context, clientID string) (int64, error) {
	bucket := time.Now().UTC().Format("2006-01-02T15:04")
	key := fmt.Sprintf("verify:rl:%s:%s", clientID, bucket)

	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("store.IncrRateLimit: %w", err)
	}

	if count == 1 {
		r.client.Expire(ctx, key, 2*time.Minute)
	}

	return count, nil
}

const orgAuthTTL = time.Hour

func orgAuthKey(clientID, regNo string) string {
	return fmt.Sprintf("verify:authorg:%s:%s", clientID, regNo)
}

// MarkOrgAuthenticated records that the given API client has successfully
// authenticated as a representative of the organization with regNo.
// Used by chain authentication: a later request for a different org may
// be accepted if this client previously authenticated to a majority-shareholder org.
func (r *Redis) MarkOrgAuthenticated(ctx context.Context, clientID, regNo string) error {
	if r == nil || clientID == "" || regNo == "" {
		return nil
	}
	if err := r.client.Set(ctx, orgAuthKey(clientID, regNo), "1", orgAuthTTL).Err(); err != nil {
		return fmt.Errorf("store.MarkOrgAuthenticated: %w", err)
	}
	return nil
}

// IsOrgAuthenticated reports whether the given client has a live authenticated
// session for the org with regNo.
func (r *Redis) IsOrgAuthenticated(ctx context.Context, clientID, regNo string) (bool, error) {
	if r == nil || clientID == "" || regNo == "" {
		return false, nil
	}
	n, err := r.client.Exists(ctx, orgAuthKey(clientID, regNo)).Result()
	if err != nil {
		return false, fmt.Errorf("store.IsOrgAuthenticated: %w", err)
	}
	return n > 0, nil
}
