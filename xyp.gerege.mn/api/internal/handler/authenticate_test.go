package handler

import (
	"testing"

	"xyp.gerege.mn/api/internal/provider"
)

func TestQualifiesAsRepresentative(t *testing.T) {
	cases := []struct {
		name string
		f    provider.OrgFounder
		want bool
	}{
		{"exactly threshold", provider.OrgFounder{SharePercent: "49"}, true},
		{"above threshold", provider.OrgFounder{SharePercent: "80"}, true},
		{"fractional above", provider.OrgFounder{SharePercent: "49.001"}, true},
		{"just below", provider.OrgFounder{SharePercent: "48.99"}, false},
		{"ten percent founder", provider.OrgFounder{SharePercent: "10"}, false},
		{"empty", provider.OrgFounder{SharePercent: ""}, false},
		{"non-numeric", provider.OrgFounder{SharePercent: "fifty"}, false},
		{"whitespace tolerated", provider.OrgFounder{SharePercent: "  51 "}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifiesAsRepresentative(tc.f); got != tc.want {
				t.Fatalf("qualifiesAsRepresentative(%q) = %v, want %v", tc.f.SharePercent, got, tc.want)
			}
		})
	}
}

// geregeEdtek mirrors the live shape of org 6658679 (Гэрэгэ эдтек) —
// CEO + two minority individual founders + one majority legal-entity founder.
func geregeEdtek() *provider.OrgInfo {
	return &provider.OrgInfo{
		RegNo:    "6658679",
		Name:     "Гэрэгэ эдтек",
		CEORegNo: "вю92071547",
		Founders: []provider.OrgFounder{
			{Name: "Батэрдэнэ Батбаяр", RegNo: "уп89020631", Type: "Иргэн", SharePercent: "10"},
			{Name: "Ганболд Батзаяа", RegNo: "уо86082617", Type: "Иргэн", SharePercent: "10"},
			{Name: "Гэрэгэ венчерс", RegNo: "8334412", Type: "Хуулийн этгээд", SharePercent: "80"},
		},
	}
}

func TestMatchRepresentative(t *testing.T) {
	info := geregeEdtek()
	cases := []struct {
		name      string
		input     string
		wantMatch bool
		wantVia   string
	}{
		{"ceo matches", "вю92071547", true, "ceo"},
		{"ceo case-insensitive", "ВЮ92071547", true, "ceo"},
		{"majority legal-entity founder matches", "8334412", true, "founder"},
		{"minority individual founder denied", "уп89020631", false, ""},
		{"unknown reg_no denied", "ук00000000", false, ""},
		{"empty denied", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMatch, gotVia := matchRepresentative(info, normalizeRegNo(tc.input))
			if gotMatch != tc.wantMatch || gotVia != tc.wantVia {
				t.Fatalf("matchRepresentative(%q) = (%v, %q), want (%v, %q)",
					tc.input, gotMatch, gotVia, tc.wantMatch, tc.wantVia)
			}
		})
	}
}

func TestQualifyingOrgFounders(t *testing.T) {
	got := qualifyingOrgFounders(geregeEdtek())
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 qualifying legal-entity founder, got %d: %+v", len(got), got)
	}
	if got[0].RegNo != "8334412" {
		t.Fatalf("expected Гэрэгэ венчерс (8334412) as chain candidate, got %q", got[0].RegNo)
	}
}

// TestMatchRepresentative_OnParent simulates the ма74101813 case:
// she's a 49% founder of Гэрэгэ венчерс (8334412) and Гэрэгэ венчерс owns
// 80% of Гэрэгэ эдтек. matchRepresentative on the parent should accept her
// — that's what the chain logic looks up at each ancestor.
func TestMatchRepresentative_OnParent(t *testing.T) {
	parent := &provider.OrgInfo{
		RegNo:    "8334412",
		Name:     "Гэрэгэ венчерс",
		CEORegNo: "уш72060800",
		Founders: []provider.OrgFounder{
			{Name: "Эрдэнэбат Цэнддорж", RegNo: "ма74101813", Type: "Иргэн", SharePercent: "49"},
			{Name: "...", RegNo: "уш72060800", Type: "Иргэн", SharePercent: "51"},
		},
	}
	if ok, via := matchRepresentative(parent, normalizeRegNo("МА74101813")); !ok || via != "founder" {
		t.Fatalf("expected ма74101813 to match parent as founder, got ok=%v via=%q", ok, via)
	}
}

func TestMaskRegNo(t *testing.T) {
	cases := map[string]string{
		"вю92071547": "вю******47",
		"8334412":    "83***12",
		"ab":         "ab",
		"":           "",
	}
	for in, want := range cases {
		if got := maskRegNo(in); got != want {
			t.Errorf("maskRegNo(%q) = %q, want %q", in, got, want)
		}
	}
}
