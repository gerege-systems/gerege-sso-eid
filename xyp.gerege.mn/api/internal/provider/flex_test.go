package provider

import (
	"encoding/json"
	"testing"
)

func TestFlexSlice(t *testing.T) {
	type wrap struct {
		Items flexSlice[orgFounderEntry] `json:"items"`
	}
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"array", `{"items":[{"sharePercent":"10"},{"sharePercent":"90"}]}`, 2},
		{"single object", `{"items":{"sharePercent":"100"}}`, 1},
		{"null", `{"items":null}`, 0},
		{"absent", `{}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w wrap
			if err := json.Unmarshal([]byte(tc.in), &w); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(w.Items) != tc.want {
				t.Fatalf("len = %d, want %d (%+v)", len(w.Items), tc.want, w.Items)
			}
		})
	}
}

func TestFlexNamed(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantName string
		wantCode string
	}{
		{"object with both fields", `{"code":"90","name":"3 хэсэг"}`, "3 хэсэг", "90"},
		{"object name only", `{"name":"Сүхбаатар"}`, "Сүхбаатар", ""},
		{"empty string treated as empty name", `""`, "", ""},
		{"non-empty string promoted to name", `"улсын зэргийн зам"`, "улсын зэргийн зам", ""},
		{"null", `null`, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n flexNamed
			if err := json.Unmarshal([]byte(tc.in), &n); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if n.Name != tc.wantName || n.Code != tc.wantCode {
				t.Fatalf("got {Code:%q Name:%q}, want {Code:%q Name:%q}",
					n.Code, n.Name, tc.wantCode, tc.wantName)
			}
		})
	}
}

// TestOrgAddressEntry_RegionAsString reproduces the org-8334412 case
// where upstream emits `"region": ""` instead of an object.
func TestOrgAddressEntry_RegionAsString(t *testing.T) {
	in := `{
		"addressStatus":"Тийм",
		"phoneNumber":"99118300",
		"stateCity":{"code":"11","name":"Улаанбаатар"},
		"soumDistrict":{"code":"19","name":"Сүхбаатар"},
		"bagKhoroo":{"code":"51","name":"1-р хороо"},
		"region":"",
		"door":"5 гудамж"
	}`
	var a orgAddressEntry
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatalf("expected entry to decode with region as empty string, got error: %v", err)
	}
	if a.StateCity.Name != "Улаанбаатар" {
		t.Errorf("StateCity.Name = %q, want %q", a.StateCity.Name, "Улаанбаатар")
	}
	if a.Region.Name != "" {
		t.Errorf("Region.Name = %q, want empty", a.Region.Name)
	}
}
