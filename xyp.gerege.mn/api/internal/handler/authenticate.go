package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"xyp.gerege.mn/api/internal/middleware"
	"xyp.gerege.mn/api/internal/provider"
)

// representThreshold is the minimum share percent (inclusive) at which a
// founder is considered able to represent the organization for authentication.
const representThreshold = 49.0

// MaxChainDepth caps recursion when traversing the ownership graph through
// legal-entity shareholders. depth=1 means only the org's direct majority
// shareholder is consulted; higher values walk further up the chain.
// 3 keeps the upstream cost bounded at well under 1s while covering
// realistic Mongolian corporate structures (holding -> sub-holding -> opco).
const MaxChainDepth = 3

// orgFounderTypeLegalEntity is the upstream value (stakeHolderTypeName) used
// to mark a founder that is itself a legal entity rather than an individual.
const orgFounderTypeLegalEntity = "Хуулийн этгээд"

// AuthenticateCitizen accepts reg_no + phone, looks up citizen from XYP,
// and returns limited verified info if found.
func (h *Handler) AuthenticateCitizen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RegNo string `json:"reg_no"`
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RegNo == "" {
		writeError(w, http.StatusBadRequest, "reg_no is required")
		return
	}
	if req.Phone == "" {
		writeError(w, http.StatusBadRequest, "phone is required")
		return
	}

	info, err := h.cfg.Citizen.Lookup(r.Context(), req.RegNo)
	if err != nil {
		slog.Error("authenticate citizen lookup failed", "error", err, "reg_no", req.RegNo)
		writeError(w, http.StatusBadGateway, "upstream service error")
		return
	}
	if info == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"reason":        "citizen not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"citizen": map[string]any{
			"reg_no":     info.RegNo,
			"civil_id":   info.CivilID,
			"last_name":  info.LastName,
			"first_name": info.FirstName,
			"gender":     info.Gender,
			"birth_date": info.BirthDate,
			"image":      info.Image,
		},
	})
}

// AuthenticateOrg accepts reg_no + ceo_reg_no and validates that the input
// reg_no can represent the organization.
//
// A request is authenticated if any of these holds:
//   - ceo_reg_no matches the registered CEO
//   - ceo_reg_no matches any founder whose share_percent >= representThreshold
//   - the API client previously authenticated (within TTL) to a legal-entity
//     founder of this org that itself qualifies under the share threshold —
//     i.e. the caller already proved authority over a parent org. This walks
//     up to MaxChainDepth levels of ownership.
func (h *Handler) AuthenticateOrg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RegNo    string `json:"reg_no"`
		CEORegNo string `json:"ceo_reg_no"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RegNo == "" {
		writeError(w, http.StatusBadRequest, "reg_no is required")
		return
	}
	if req.CEORegNo == "" {
		writeError(w, http.StatusBadRequest, "ceo_reg_no is required")
		return
	}

	info, err := h.cfg.Org.Lookup(r.Context(), req.RegNo)
	if err != nil {
		slog.Error("authenticate org lookup failed", "error", err, "reg_no", req.RegNo)
		writeError(w, http.StatusBadGateway, "upstream service error")
		return
	}
	if info == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"reason":        "organization not found",
		})
		return
	}

	clientID, _ := r.Context().Value(middleware.ClientIDKey).(string)
	inputRegNo := normalizeRegNo(req.CEORegNo)

	matched, via := matchRepresentative(info, inputRegNo)

	if !matched {
		viaChain, parentRegNo := h.matchViaChain(r.Context(), clientID, info, inputRegNo, MaxChainDepth)
		if viaChain {
			matched = true
			via = "majority_shareholder_org:" + parentRegNo
		}
	}

	if !matched {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":   false,
			"reason":          "ceo_reg_no does not match any authorized representative",
			"representatives": representativeIdentifiers(info),
		})
		return
	}

	if h.cfg.Redis != nil {
		if err := h.cfg.Redis.MarkOrgAuthenticated(r.Context(), clientID, info.RegNo); err != nil {
			slog.Warn("mark org authenticated failed", "error", err, "client_id", clientID, "reg_no", info.RegNo)
		}
	}

	// Surface the matched path to the audit middleware via response header.
	// The header is also useful for callers that want to log how the
	// authentication succeeded.
	w.Header().Set("X-Auth-Via", via)

	result := map[string]any{
		"authenticated": true,
		"via":           via,
		"organization": map[string]any{
			"reg_no":       info.RegNo,
			"name":         info.Name,
			"type":         info.Type,
			"ceo":          info.CEO,
			"ceo_reg_no":   info.CEORegNo,
			"ceo_position": info.CEOPosition,
		},
		"representatives": representativeIdentifiers(info),
	}

	if top := findLargestFounder(info.Founders); top != nil {
		result["owner"] = map[string]any{
			"name":          top.Name,
			"reg_no":        top.RegNo,
			"type":          top.Type,
			"share_percent": top.SharePercent,
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// matchRepresentative checks whether the supplied reg_no matches the CEO or a
// qualifying founder. Returns the role label that matched.
func matchRepresentative(info *provider.OrgInfo, inputRegNo string) (bool, string) {
	if strings.EqualFold(normalizeRegNo(info.CEORegNo), inputRegNo) {
		return true, "ceo"
	}
	for i := range info.Founders {
		if !qualifiesAsRepresentative(info.Founders[i]) {
			continue
		}
		if strings.EqualFold(normalizeRegNo(info.Founders[i].RegNo), inputRegNo) {
			return true, "founder"
		}
	}
	return false, ""
}

// matchViaChain decides whether `inputRegNo` may represent `info` by walking
// up the ownership graph through qualifying legal-entity founders.
//
// Two paths are considered at each ancestor:
//
//  1. Caller-scoped session — if the API client previously authenticated as a
//     representative of the ancestor (Redis), accept immediately. This is the
//     fast path and avoids upstream calls when the caller already proved
//     authority earlier in the same session.
//
//  2. Transitive ownership — load the ancestor from upstream and check
//     whether `inputRegNo` is the ancestor's CEO or a 49%+ founder. This
//     covers the common Mongolian holding structure ("citizen X owns 50% of
//     Holding A, Holding A owns 80% of Operating Co B" — X represents B).
//
// BFS, cycle-safe (visited set), bounded by maxDepth so a malformed
// ownership graph cannot drive unbounded upstream calls.
func (h *Handler) matchViaChain(ctx context.Context, clientID string, info *provider.OrgInfo, inputRegNo string, maxDepth int) (bool, string) {
	if maxDepth <= 0 {
		return false, ""
	}

	visited := map[string]struct{}{normalizeRegNo(info.RegNo): {}}
	frontier := qualifyingOrgFounders(info)

	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		var next []provider.OrgFounder
		for _, parent := range frontier {
			parentReg := normalizeRegNo(parent.RegNo)
			if parentReg == "" {
				continue
			}
			if _, seen := visited[parentReg]; seen {
				continue
			}
			visited[parentReg] = struct{}{}

			// Fast path: caller has an existing session for this ancestor.
			if h.cfg.Redis != nil && clientID != "" {
				ok, err := h.cfg.Redis.IsOrgAuthenticated(ctx, clientID, parent.RegNo)
				if err != nil {
					slog.Warn("chain auth lookup failed", "error", err, "client_id", clientID, "reg_no", parent.RegNo)
				} else if ok {
					return true, parent.RegNo
				}
			}

			// Transitive path: pull the ancestor and try direct match there.
			parentInfo, err := h.cfg.Org.Lookup(ctx, parent.RegNo)
			if err != nil {
				slog.Warn("chain parent lookup failed", "error", err, "reg_no", parent.RegNo)
				continue
			}
			if parentInfo == nil {
				continue
			}
			if ok, _ := matchRepresentative(parentInfo, inputRegNo); ok {
				return true, parent.RegNo
			}
			if depth+1 < maxDepth {
				next = append(next, qualifyingOrgFounders(parentInfo)...)
			}
		}
		frontier = next
	}
	return false, ""
}

// qualifiesAsRepresentative reports whether a founder's stake is at or above
// the representation threshold. share_percent that fails to parse is treated
// as not qualifying — better to deny than to over-grant.
func qualifiesAsRepresentative(f provider.OrgFounder) bool {
	pct, err := strconv.ParseFloat(strings.TrimSpace(f.SharePercent), 64)
	if err != nil {
		return false
	}
	return pct >= representThreshold
}

// qualifyingOrgFounders returns the subset of founders that are themselves
// legal entities and meet the share threshold — the only kind that can
// participate in chain authentication, since chain auth means
// "the caller already authenticated as a representative of that org".
func qualifyingOrgFounders(info *provider.OrgInfo) []provider.OrgFounder {
	out := make([]provider.OrgFounder, 0, len(info.Founders))
	for i := range info.Founders {
		f := info.Founders[i]
		if !qualifiesAsRepresentative(f) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(f.Type), orgFounderTypeLegalEntity) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// representativeIdentifiers lists the reg_nos that would satisfy direct
// authentication — useful for callers debugging a denied request without
// exposing the full org record.
func representativeIdentifiers(info *provider.OrgInfo) []map[string]string {
	reps := make([]map[string]string, 0, 1+len(info.Founders))
	if info.CEORegNo != "" {
		reps = append(reps, map[string]string{
			"role":   "ceo",
			"reg_no": maskRegNo(info.CEORegNo),
		})
	}
	for i := range info.Founders {
		f := info.Founders[i]
		if !qualifiesAsRepresentative(f) {
			continue
		}
		reps = append(reps, map[string]string{
			"role":          "founder",
			"reg_no":        maskRegNo(f.RegNo),
			"share_percent": f.SharePercent,
			"type":          f.Type,
		})
	}
	return reps
}

// maskRegNo hides the middle of a reg_no so a denied caller can confirm
// they're targeting the right person without leaking PII. Rune-aware so
// Cyrillic citizen reg_nos (10 chars / 12+ bytes) keep their visible head
// and tail at the expected character positions.
func maskRegNo(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= 4 {
		return s
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-4) + string(r[len(r)-2:])
}

func normalizeRegNo(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func findLargestFounder(founders []provider.OrgFounder) *provider.OrgFounder {
	if len(founders) == 0 {
		return nil
	}
	var top *provider.OrgFounder
	var topPct float64
	for i := range founders {
		pct, _ := strconv.ParseFloat(founders[i].SharePercent, 64)
		if top == nil || pct > topPct {
			top = &founders[i]
			topPct = pct
		}
	}
	return top
}
