package handler

import (
	"encoding/json"
	"net/http"

	"xyp.gerege.mn/api/internal/provider"
	"xyp.gerege.mn/api/internal/store"
)

type Config struct {
	DB       *store.Postgres
	Redis    *store.Redis
	AdminKey string
	Citizen  provider.CitizenProvider
	Org      provider.OrgProvider
	Finger   provider.FingerProvider
}

type Handler struct {
	cfg Config
}

func New(cfg Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "xyp.gerege.mn"})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
