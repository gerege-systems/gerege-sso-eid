package handler

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
)

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if h.cfg.AdminKey == "" {
		h.jsonError(w, 403, "admin not configured")
		return false
	}
	auth := r.Header.Get("Authorization")
	expected := "Bearer " + h.cfg.AdminKey
	if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
		h.jsonError(w, 401, "unauthorized")
		return false
	}
	return true
}

func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}

	clients, err := h.cfg.DB.ListDANClients(r.Context())
	if err != nil {
		slog.Error("clients: list", "error", err)
		h.jsonError(w, 500, "internal error")
		return
	}
	if clients == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}

	var req struct {
		Name         string   `json:"name"`
		CallbackURLs []string `json:"callback_urls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, 400, "invalid JSON body")
		return
	}
	if req.Name == "" {
		h.jsonError(w, 400, "name is required")
		return
	}
	if len(req.CallbackURLs) == 0 {
		h.jsonError(w, 400, "at least one callback_url is required")
		return
	}

	client, secret, hmacKey, err := h.cfg.DB.CreateDANClient(r.Context(), req.Name, req.CallbackURLs)
	if err != nil {
		slog.Error("clients: create", "error", err)
		h.jsonError(w, 500, "internal error")
		return
	}

	slog.Info("client created", "id", client.ID, "name", req.Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id":            client.ID,
		"secret":        secret,
		"hmac_key":      hmacKey,
		"name":          client.Name,
		"callback_urls": client.CallbackURLs,
		"message":       "secret болон hmac_key-ийг хадгалж авна уу. Дахин харагдахгүй.",
	})
}

func (h *Handler) RegenerateClientSecret(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		h.jsonError(w, 400, "client id required")
		return
	}

	secret, err := h.cfg.DB.RegenerateDANClientSecret(r.Context(), id)
	if err != nil {
		slog.Error("clients: regenerate secret", "error", err)
		h.jsonError(w, 500, "internal error")
		return
	}
	if secret == "" {
		h.jsonError(w, 404, "client not found")
		return
	}

	slog.Info("client secret regenerated", "id", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":      id,
		"secret":  secret,
		"message": "Шинэ secret-ийг хадгалж авна уу. Дахин харагдахгүй. Хуучин secret хүчингүй боллоо.",
	})
}

func (h *Handler) DeactivateClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		h.jsonError(w, 400, "client id required")
		return
	}

	if err := h.cfg.DB.DeactivateDANClient(r.Context(), id); err != nil {
		slog.Error("clients: deactivate", "error", err)
		h.jsonError(w, 500, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deactivated", "id": id})
}
