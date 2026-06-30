package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"xyp.gerege.mn/api/internal/provider"
)

// CitizenFinger verifies a fingerprint against a reg_no via the eSign
// service and returns the matched citizen's info.
func (h *Handler) CitizenFinger(w http.ResponseWriter, r *http.Request) {
	var req provider.FingerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RegNo == "" {
		writeError(w, http.StatusBadRequest, "reg_no is required")
		return
	}

	info, err := h.cfg.Finger.CheckFinger(r.Context(), req)
	if err != nil {
		slog.Error("citizen finger check failed", "error", err, "reg_no", req.RegNo)
		writeError(w, http.StatusBadGateway, "upstream service error")
		return
	}

	if info == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"matched": false,
			"citizen": nil,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"matched": true,
		"citizen": info,
	})
}
