package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FingerReq is the fingerprint-check request. It mirrors the upstream
// /esign/check payload one-to-one (finger_byte + reg_no), so it can be
// both the inbound API body and the outbound upstream body.
type FingerReq struct {
	FingerByte string `json:"finger_byte"`
	RegNo      string `json:"reg_no"`
}

// FingerInfo is our normalized output for the eSign fingerprint-check
// endpoint. Field names are the snake_case form of the upstream result
// object so callers get a stable, predictable shape.
type FingerInfo struct {
	RegNo         string `json:"reg_no"`
	Surname       string `json:"surname,omitempty"`         // surName
	ForeName      string `json:"fore_name,omitempty"`       // foreName
	GivenName     string `json:"given_name,omitempty"`      // givenName
	CivilID       int64  `json:"civil_id,omitempty"`        // civilId
	RegisteredNum int64  `json:"registered_num,omitempty"`  // registeredNum
	Citizenship   string `json:"citizenship,omitempty"`     // citizenship
	IsCountry     int    `json:"is_country,omitempty"`      // isCountry
	SexCode       string `json:"sex_code,omitempty"`        // sexCode
	SexName       string `json:"sex_name,omitempty"`        // sexName
	AimagCityName string `json:"aimag_city_name,omitempty"` // aimagCityName
	AddressID     int64  `json:"address_id,omitempty"`      // addressId
	AddressDetail string `json:"address_detail,omitempty"`  // addressDetail
	AddressLog    string `json:"address_log,omitempty"`     // addressLog
}

// fingerResult maps the upstream /esign/check result object.
type fingerResult struct {
	RegisterNum   string `json:"registerNum"`
	SurName       string `json:"surName"`
	ForeName      string `json:"foreName"`
	GivenName     string `json:"givenName"`
	CivilID       int64  `json:"civilId"`
	RegisteredNum int64  `json:"registeredNum"`
	Citizenship   string `json:"citizenship"`
	IsCountry     int    `json:"isCountry"`
	SexCode       string `json:"sexCode"`
	SexName       string `json:"sexName"`
	AimagCityName string `json:"aimagCityName"`
	AddressID     int64  `json:"addressId"`
	AddressDetail string `json:"addressDetail"`
	AddressLog    string `json:"addressLog"`
}

type FingerProvider interface {
	// CheckFinger verifies a fingerprint against a reg_no and returns the
	// matched citizen's info, or nil when the upstream reports no match.
	CheckFinger(ctx context.Context, req FingerReq) (*FingerInfo, error)
}

// EsignHTTP talks to the eSign fingerprint service, which lives on a
// separate host from the main XYP upstream (10.0.0.63:8003 vs 10.0.0.187:8000).
type EsignHTTP struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func NewEsignHTTP(baseURL, apiKey string) *EsignHTTP {
	return &EsignHTTP{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

// CheckFinger calls POST {baseURL}/esign/check with {"finger_byte":"...","reg_no":"..."}.
// Upstream wraps data in {"code":200,"status":"success","message":"...","result":{...}}.
func (c *EsignHTTP) CheckFinger(ctx context.Context, fr FingerReq) (*FingerInfo, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("esign API not configured")
	}

	body, _ := json.Marshal(fr)
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/esign/check", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("finger check request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("finger check: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	// Upstream returns a non-200 with {"status":"error"} when the fingerprint
	// does not match or the citizen is not found — treat that as "no match"
	// rather than a transport error.
	if resp.StatusCode != http.StatusOK {
		var env struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(respBody, &env) == nil && env.Status == "error" {
			return nil, nil
		}
		return nil, fmt.Errorf("finger check status %d: %s", resp.StatusCode, string(respBody))
	}

	var env struct {
		Code   int          `json:"code"`
		Status string       `json:"status"`
		Result fingerResult `json:"result"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("finger check decode: %w", err)
	}
	if env.Status != "success" || env.Code != 200 {
		return nil, nil
	}

	r := env.Result
	return &FingerInfo{
		RegNo:         r.RegisterNum,
		Surname:       r.SurName,
		ForeName:      r.ForeName,
		GivenName:     r.GivenName,
		CivilID:       r.CivilID,
		RegisteredNum: r.RegisteredNum,
		Citizenship:   r.Citizenship,
		IsCountry:     r.IsCountry,
		SexCode:       r.SexCode,
		SexName:       r.SexName,
		AimagCityName: r.AimagCityName,
		AddressID:     r.AddressID,
		AddressDetail: r.AddressDetail,
		AddressLog:    r.AddressLog,
	}, nil
}
