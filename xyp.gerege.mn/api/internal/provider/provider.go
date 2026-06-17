package provider

import (
	"bytes"
	"context"
	"encoding/json"
)

// CitizenInfo is our normalized output for the citizen lookup endpoint.
type CitizenInfo struct {
	RegNo           string `json:"reg_no"`
	LastName        string `json:"last_name"`
	FirstName       string `json:"first_name"`
	Surname         string `json:"surname,omitempty"`
	Gender          string `json:"gender,omitempty"`
	BirthDate       string `json:"birth_date,omitempty"`
	BirthPlace      string `json:"birth_place,omitempty"`
	Nationality     string `json:"nationality,omitempty"`
	CivilID         string `json:"civil_id,omitempty"`
	PassportNum     string `json:"passport_num,omitempty"`
	PassportAddress string `json:"passport_address,omitempty"`
	Image           string `json:"image,omitempty"`
}

// citizenResult maps the upstream /user/validate result object.
type citizenResult struct {
	Firstname       string `json:"firstname"`
	Lastname        string `json:"lastname"`
	Surname         string `json:"surname"`
	Regnum          string `json:"regnum"`
	Gender          string `json:"gender"`
	BirthDate       string `json:"birthDateAsText"`
	BirthPlace      string `json:"birthPlace"`
	Nationality     string `json:"nationality"`
	CivilID         string `json:"civilId"`
	PassportNum     string `json:"passportNum"`
	PassportAddress string `json:"passportAddress"`
	Image           string `json:"image"`
	ResultCode      int    `json:"resultCode"`
}

type CitizenVerifyReq struct {
	RegNo     string `json:"reg_no"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// OrgInfo is our normalized output for the org lookup endpoint.
type OrgInfo struct {
	RegNo        string           `json:"reg_no"`
	Name         string           `json:"name"`
	Type         string           `json:"type,omitempty"`
	Capital      string           `json:"capital,omitempty"`
	CEO          string           `json:"ceo,omitempty"`
	CEORegNo     string           `json:"ceo_reg_no,omitempty"`
	CEOPosition  string           `json:"ceo_position,omitempty"`
	Phone        string           `json:"phone,omitempty"`
	Address      string           `json:"address,omitempty"`
	Industry     []string         `json:"industry,omitempty"`
	Founders     []OrgFounder     `json:"founders,omitempty"`
	StakeHolders []OrgStakeHolder `json:"stake_holders,omitempty"`
}

type OrgFounder struct {
	Name         string `json:"name"`
	RegNo        string `json:"reg_no"`
	Type         string `json:"type"`
	SharePercent string `json:"share_percent"`
}

type OrgStakeHolder struct {
	Name     string `json:"name"`
	RegNo    string `json:"reg_no"`
	Position string `json:"position"`
}

// flexSlice decodes JSON that may be either an array of T or a single T.
// The upstream /legalentity/info API omits the array wrapper whenever a
// field has exactly one element — org 6884857 for instance has a single
// address entry and the upstream returns it as a bare object, not a
// one-element array. Naive []T unmarshal fails with "cannot unmarshal
// object into Go struct field ... of type []struct{...}". This mirrors
// the `toArray` helper already used by the admin UI TS routes.
type flexSlice[T any] []T

func (s *flexSlice[T]) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '[' {
		return json.Unmarshal(data, (*[]T)(s))
	}
	var single T
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*s = []T{single}
	return nil
}

// flexNamed decodes a `{code, name}` JSON object that the upstream may
// emit as an empty string ("") when the field is unset — org 8334412 for
// example has `"region": ""` while populated entries are
// `{"code":"90","name":"3 хэсэг"}`. Naive struct unmarshal fails with
// "cannot unmarshal string into Go struct field ... of type struct{...}".
// We treat any string (empty or not) as a `name` and otherwise decode the
// object normally.
type flexNamed struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func (n *flexNamed) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		n.Name = s
		return nil
	}
	type alias flexNamed
	return json.Unmarshal(data, (*alias)(n))
}

type orgAddressEntry struct {
	AddressStatus string    `json:"addressStatus"`
	PhoneNumber   string    `json:"phoneNumber"`
	StateCity     flexNamed `json:"stateCity"`
	SoumDistrict  flexNamed `json:"soumDistrict"`
	BagKhoroo     flexNamed `json:"bagKhoroo"`
	Region        flexNamed `json:"region"`
	Door          string    `json:"door"`
}

type orgCapitalEntry struct {
	RowStatusName string `json:"rowStatusName"`
	TotalAmount   string `json:"totalAmount"`
}

type orgChangeNameEntry struct {
	RequestedName string `json:"requestedName"`
	CompanyType   string `json:"companyType"`
	CompanyRegnum string `json:"companyRegnum"`
}

type orgIndutyEntry struct {
	IndustryName   string `json:"industryName"`
	IndustryStatus string `json:"industryStatus"`
}

type orgFounderEntry struct {
	FirstName           string `json:"firstName"`
	LastName            string `json:"lastName"`
	StakeHolderRegnum   string `json:"stakeHolderRegnum"`
	StakeHolderTypeName string `json:"stakeHolderTypeName"`
	SharePercent        string `json:"sharePercent"`
	Status              string `json:"status"`
}

type orgStakeHolderEntry struct {
	Firstname    string `json:"firstname"`
	Lastname     string `json:"lastname"`
	StateRegnum  string `json:"stateRegnum"`
	PositionName string `json:"positionName"`
	Status       string `json:"status"`
}

// orgResult maps the upstream /legalentity/info result object.
// All slice fields use flexSlice so a single-element response without the
// array wrapper still decodes cleanly.
type orgResult struct {
	ResultCode   int                            `json:"resultCode"`
	GeneralR     orgCEO                         `json:"generalR"`
	Address      flexSlice[orgAddressEntry]     `json:"address"`
	Capital      flexSlice[orgCapitalEntry]     `json:"capital"`
	ChangeName   flexSlice[orgChangeNameEntry]  `json:"changeName"`
	Induty       flexSlice[orgIndutyEntry]      `json:"induty"`
	Founder      flexSlice[orgFounderEntry]     `json:"founder"`
	StakeHolders flexSlice[orgStakeHolderEntry] `json:"stakeHolders"`
}

type orgCEO struct {
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Regnum       string `json:"regnum"`
	PositionName string `json:"positionName"`
}

type OrgVerifyReq struct {
	RegNo string `json:"reg_no"`
	Name  string `json:"name"`
}

type CitizenProvider interface {
	Lookup(ctx context.Context, regNo string) (*CitizenInfo, error)
	Verify(ctx context.Context, req CitizenVerifyReq) (bool, error)
}

type OrgProvider interface {
	Lookup(ctx context.Context, regNo string) (*OrgInfo, error)
	Verify(ctx context.Context, req OrgVerifyReq) (bool, error)
}
