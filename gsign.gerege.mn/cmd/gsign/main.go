package main

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.mozilla.org/pkcs7"
)

type config struct {
	EsignToken string // Basic auth token for MSSP
	MSSPUrl    string // MSSP REST endpoint
	Port       string
	AppURL     string // e.g. https://gsign.gerege.mn
}

func main() {
	slog.Info("starting gsign.gerege.mn")

	cfg := config{
		EsignToken: envOrDefault("ESIGN_TOKEN", ""),
		MSSPUrl:    envOrDefault("MSSP_URL", "https://66.181.165.212:9061/rest/service"),
		Port:       envOrDefault("PORT", "8445"),
		AppURL:     envOrDefault("APP_URL", "https://gsign.gerege.mn"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /sign", signHandler(cfg))
	mux.HandleFunc("GET /verify", verifyPageHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"gsign.gerege.mn"}`))
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" rx="10" fill="#7c3aed"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-family="sans-serif" font-weight="700" font-size="11">G</text></svg>`))
	})

	addr := ":" + cfg.Port
	srv := &http.Server{
		Addr:         addr,
		Handler:      corsMiddleware(logMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second, // G-Sign can take up to 2 min (user PIN entry)
	}

	go func() {
		slog.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// =====================
// Handlers
// =====================

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexPage)
}

func verifyPageHandler(w http.ResponseWriter, r *http.Request) {
	callbackURL := r.URL.Query().Get("callback_url")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, verifyPage, callbackURL)
}

// signHandler receives phone number, calls MSSP, parses certificate, returns citizen data
func signHandler(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PhoneNo     string `json:"phoneNo"`
			CallbackURL string `json:"callbackUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, 400, "JSON parse error")
			return
		}
		if req.PhoneNo == "" {
			jsonErr(w, 400, "phoneNo шаардлагатай")
			return
		}

		// Clean phone number
		phone := strings.TrimSpace(req.PhoneNo)
		if !strings.HasPrefix(phone, "+976") {
			phone = "+976" + phone
		}

		slog.Info("sign: requesting signature", "phone", phone)

		// Step 1: Send MSS_SignatureReq to MSSP
		msspReq := map[string]any{
			"MSS_SignatureReq": map[string]any{
				"AdditionalServices": []map[string]any{
					{"Description": "http://uri.etsi.org/TS102204/v1.1.2#validate"},
				},
				"DataToBeDisplayed": map[string]any{
					"Data":     "Gerege: Та гарын үсгээ оруулна уу",
					"Encoding": "UTF-8",
					"MimeType": "text/plain",
				},
				"DataToBeSigned": map[string]any{
					"Data":     "gerege",
					"Encoding": "UTF-8",
					"MimeType": "text/plain",
				},
				"MessagingMode": "synch",
				"MobileUser": map[string]any{
					"MSISDN": phone,
				},
				"SignatureProfile": "http://alauda.mobi/nonRepudiation",
			},
		}

		msspBody, _ := json.Marshal(msspReq)

		// MSSP uses self-signed cert — skip TLS verify
		httpClient := &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		httpReq, err := http.NewRequest("POST", cfg.MSSPUrl, strings.NewReader(string(msspBody)))
		if err != nil {
			slog.Error("sign: create request failed", "error", err)
			jsonErr(w, 500, "Internal error")
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Basic "+cfg.EsignToken)

		resp, err := httpClient.Do(httpReq)
		if err != nil {
			slog.Error("sign: MSSP request failed", "error", err)
			jsonErr(w, 502, "G-Sign бүртгэлгүй эсвэл хүсэлт цуцлагдсан.")
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		slog.Info("sign: MSSP response", "status", resp.StatusCode)

		if resp.StatusCode != http.StatusOK {
			slog.Error("sign: MSSP error", "status", resp.StatusCode, "body", string(body))
			jsonErr(w, 502, "G-Sign бүртгэлгүй эсвэл мэдээлэл буруу байна.")
			return
		}

		// Step 2: Parse MSSP response
		var msspResp struct {
			MSSSignatureResp struct {
				MSSSignature struct {
					Base64Signature string `json:"Base64Signature"`
				} `json:"MSS_Signature"`
				Status struct {
					StatusCode struct {
						Value string `json:"Value"`
					} `json:"StatusCode"`
					StatusMessage string `json:"StatusMessage"`
				} `json:"Status"`
			} `json:"MSS_SignatureResp"`
			// The MSSP signals errors as an ETSI/SOAP-style Fault carried inside
			// an HTTP 200 body (e.g. a blocked PIN), not via a non-200 status.
			Fault *struct {
				Reason string `json:"Reason"`
				Detail string `json:"Detail"`
			} `json:"Fault"`
		}

		if err := json.Unmarshal(body, &msspResp); err != nil {
			slog.Error("sign: parse MSSP response failed", "error", err)
			jsonErr(w, 502, "MSSP хариу задлах алдаа.")
			return
		}

		// Surface the real fault reason (blocked PIN, cancelled, not registered…)
		// instead of masking every failure as a generic "signature missing".
		if msspResp.Fault != nil && (msspResp.Fault.Reason != "" || msspResp.Fault.Detail != "") {
			slog.Error("sign: MSSP fault", "reason", msspResp.Fault.Reason, "detail", msspResp.Fault.Detail)
			jsonErr(w, 502, msspFaultMessage(msspResp.Fault.Reason, msspResp.Fault.Detail))
			return
		}

		base64Sig := msspResp.MSSSignatureResp.MSSSignature.Base64Signature
		if base64Sig == "" {
			slog.Error("sign: empty signature in response", "body", string(body))
			jsonErr(w, 502, "G-Sign гарын үсэг авагдсангүй.")
			return
		}

		// Step 3: Decode CMS/PKCS7 signature and extract certificate info (pure Go)
		citizenData, err := parseCMSSignature(base64Sig)
		if err != nil {
			slog.Error("sign: CMS parse failed", "error", err)
			jsonErr(w, 502, "Тоон гарын үсгийн сертификат задлах алдаа.")
			return
		}

		slog.Info("sign: success", "reg_no", citizenData["serialnumber"], "cn", citizenData["cn"])

		// Step 4: If callback_url provided, redirect with data
		if req.CallbackURL != "" {
			redirectURL, err := url.Parse(req.CallbackURL)
			if err == nil {
				params := redirectURL.Query()
				for k, v := range citizenData {
					if v != "" {
						params.Set(k, v)
					}
				}
				params.Set("timestamp", fmt.Sprintf("%d", time.Now().Unix()))
				redirectURL.RawQuery = params.Encode()

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"success":     true,
					"redirectUrl": redirectURL.String(),
					"citizen":     citizenData,
				})
				return
			}
		}

		// No callback — return citizen data as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"citizen": citizenData,
		})
	}
}

// =====================
// CMS/PKCS7 parsing
// =====================

// parseCMSSignature decodes a base64 CMS/PKCS7 signature and extracts
// the signer certificate's SubjectDN fields as a map.
func parseCMSSignature(base64Sig string) (map[string]string, error) {
	derBytes, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		// Try raw base64 (no padding)
		derBytes, err = base64.RawStdEncoding.DecodeString(base64Sig)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}

	p7, err := pkcs7.Parse(derBytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs7 parse: %w", err)
	}

	if len(p7.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates in CMS")
	}

	cert := p7.Certificates[0]
	result := parseDN(cert.Subject)

	// Raw DN strings for debugging
	result["subject_dn"] = cert.Subject.String()
	result["issuer_dn"] = cert.Issuer.String()

	// Issuer fields
	issuerData := parseDN(cert.Issuer)
	for k, v := range issuerData {
		result["issuer_"+k] = v
	}

	// Add validity info
	result["not_before"] = cert.NotBefore.Format(time.RFC3339)
	result["not_after"] = cert.NotAfter.Format(time.RFC3339)
	result["is_valid"] = fmt.Sprintf("%v", cert.NotAfter.After(time.Now()))

	// Certificate serial number (hex)
	result["cert_serial"] = cert.SerialNumber.Text(16)

	// Signed data
	if p7.Content != nil {
		result["signed_data"] = string(p7.Content)
	}

	// Log ALL Name entries for debugging
	for i, name := range cert.Subject.Names {
		oid := name.Type.String()
		val := fmt.Sprintf("%v", name.Value)
		slog.Info("cert subject name", "index", i, "oid", oid, "value", val)
		// Also store all OIDs in result
		result[fmt.Sprintf("oid_%s", oid)] = val
	}

	return result, nil
}

// parseDN extracts fields from x509 Subject into a flat map.
// SubjectDN from G-Sign typically contains:
//
//	SERIALNUMBER=РД98012345 (reg_no), CN=НЭРГҮЙ (name), ...
func parseDN(subject pkix.Name) map[string]string {
	result := make(map[string]string)

	if subject.SerialNumber != "" {
		result["serialnumber"] = subject.SerialNumber
		result["reg_no"] = subject.SerialNumber
	}
	if subject.CommonName != "" {
		result["cn"] = subject.CommonName
	}
	for _, name := range subject.Names {
		oid := name.Type.String()
		val := fmt.Sprintf("%v", name.Value)
		switch oid {
		case "2.5.4.3": // CN
			result["cn"] = val
		case "2.5.4.4": // Surname
			result["surname"] = val
		case "2.5.4.5": // SerialNumber
			result["serialnumber"] = val
			result["reg_no"] = val
		case "2.5.4.6": // Country
			result["country"] = val
		case "2.5.4.7": // Locality
			result["locality"] = val
		case "2.5.4.8": // State/Province
			result["state"] = val
		case "2.5.4.10": // Organization
			result["organization"] = val
		case "2.5.4.11": // OrganizationalUnit
			result["ou"] = val
		case "2.5.4.42": // GivenName
			result["given_name"] = val
		}
	}

	// If CN contains full name and no given_name parsed, try to split
	if result["given_name"] == "" && result["cn"] != "" {
		parts := strings.Fields(result["cn"])
		if len(parts) >= 2 {
			result["family_name"] = parts[0]
			result["given_name"] = strings.Join(parts[1:], " ")
		} else if len(parts) == 1 {
			result["given_name"] = parts[0]
		}
	}
	if result["surname"] != "" && result["family_name"] == "" {
		result["family_name"] = result["surname"]
	}

	return result
}

// =====================
// Helpers
// =====================

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// msspFaultMessage maps an ETSI MSS fault reason to a user-facing Mongolian
// message, falling back to the MSSP-provided detail/reason text.
func msspFaultMessage(reason, detail string) string {
	switch reason {
	case "PIN_NR_BLOCKED":
		return "Таны G-Sign гарын үсгийн PIN блоклогдсон байна. Гар утасны операторт хандаж тайлуулна уу."
	case "USER_CANCEL":
		return "Хэрэглэгч гарын үсэг зурах хүсэлтийг цуцалсан."
	case "EXPIRED_TRANSACTION":
		return "Хүсэлтийн хугацаа дууссан. Дахин оролдоно уу."
	case "WRONG_PARAM", "UNKNOWN_CLIENT", "NO_KEY_FOUND":
		return "Энэ дугаар G-Sign-д бүртгэлгүй эсвэл мэдээлэл буруу байна."
	}
	if detail != "" {
		return "G-Sign алдаа: " + detail
	}
	if reason != "" {
		return "G-Sign алдаа: " + reason
	}
	return "G-Sign гарын үсэг авагдсангүй."
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "ip", r.RemoteAddr, "latency_ms", time.Since(start).Milliseconds())
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// =====================
// HTML Templates
// =====================

const indexPage = `<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>G-Sign Gateway — gsign.gerege.mn</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0b1120;color:#e2e8f0;min-height:100vh}
nav{display:flex;align-items:center;justify-content:space-between;padding:16px 32px;border-bottom:1px solid rgba(255,255,255,.06)}
.nav-logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;color:#fff}
.nav-logo svg{width:32px;height:32px}
.nav-links{display:flex;gap:24px}
.nav-links a{color:#94a3b8;font-size:13px;text-decoration:none;font-weight:500}
.nav-links a:hover{color:#fff}
.hero{text-align:center;padding:80px 24px 48px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 16px;background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.2);border-radius:24px;font-size:12px;color:#a78bfa;font-weight:500;margin-bottom:32px}
.hero h1{font-size:48px;font-weight:800;line-height:1.1;margin-bottom:20px;color:#fff}
.hero h1 span{background:linear-gradient(135deg,#8b5cf6,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{max-width:640px;margin:0 auto 16px;color:#94a3b8;font-size:16px;line-height:1.7}
.hero .sub{font-size:13px;color:#64748b;margin-bottom:40px}

.sign-form{max-width:400px;margin:0 auto;text-align:left}
.form-label{display:block;font-size:13px;color:#94a3b8;margin-bottom:6px;font-weight:500}
.phone-row{display:flex;gap:8px;margin-bottom:16px}
.phone-prefix{padding:14px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:12px;color:#94a3b8;font-size:15px;font-weight:600;white-space:nowrap}
.phone-input{flex:1;padding:14px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:12px;color:#fff;font-size:15px;outline:none}
.phone-input:focus{border-color:#7c3aed}
.phone-input::placeholder{color:#475569}
.sign-btn{width:100%;padding:16px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;font-weight:700;font-size:16px;border:none;border-radius:14px;cursor:pointer;transition:all .2s;box-shadow:0 4px 20px rgba(124,58,237,.3)}
.sign-btn:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(124,58,237,.4)}
.sign-btn:disabled{opacity:.6;cursor:not-allowed;transform:none;box-shadow:none}
.sign-hint{text-align:center;margin-top:16px;font-size:12px;color:#475569}
.status{margin-top:16px;padding:16px;border-radius:12px;font-size:14px;display:none;text-align:center}
.status.loading{display:block;background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.2);color:#a78bfa}
.status.success{display:block;background:rgba(22,163,74,.1);border:1px solid rgba(22,163,74,.2);color:#4ade80}
.status.error{display:block;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#f87171}

.result{max-width:600px;margin:32px auto 0;display:none}
.result.show{display:block}
.result-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:16px;overflow:hidden}
.result-header{padding:20px;background:rgba(22,163,74,.08);border-bottom:1px solid rgba(22,163,74,.15);text-align:center}
.result-header h3{color:#4ade80;font-size:16px;font-weight:700}
.result-body{padding:20px}
.result-row{display:flex;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.result-row:last-child{border-bottom:none}
.result-label{width:140px;font-size:13px;font-weight:600;color:#94a3b8}
.result-value{flex:1;font-size:13px;color:#fff}
.result-json{margin-top:16px}
.result-json pre{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;font-size:12px;overflow-x:auto;color:#e2e8f0;line-height:1.6;max-height:300px;overflow-y:auto}

.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;max-width:900px;margin:60px auto 0;padding:0 24px}
.feature{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:28px}
.feature-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;margin-bottom:16px;font-size:20px}
.feature-icon.purple{background:rgba(124,58,237,.1);color:#a78bfa}
.feature-icon.green{background:rgba(22,163,74,.1);color:#4ade80}
.feature-icon.amber{background:rgba(245,158,11,.1);color:#fbbf24}
.feature h3{font-size:15px;font-weight:700;color:#fff;margin-bottom:8px}
.feature p{font-size:13px;color:#94a3b8;line-height:1.6;margin:0}
.footer{text-align:center;padding:48px 24px 32px;font-size:12px;color:#475569}
.footer a{color:#a78bfa;text-decoration:none}
@media(max-width:640px){.hero h1{font-size:32px}.features{grid-template-columns:1fr}}
</style>
</head>
<body>
<nav>
  <div class="nav-logo">
    <svg viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#7c3aed"/><text x="50%%" y="55%%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-family="sans-serif" font-weight="800" font-size="13">G</text></svg>
    G-Sign Gateway
  </div>
  <div class="nav-links">
    <a href="/">Тойм</a>
    <a href="https://dan.gerege.mn/docs">DAN Docs</a>
  </div>
</nav>

<div class="hero">
  <div class="badge">Gerege Systems LLC</div>
  <h1>G-Sign <span>Verify</span></h1>
  <p>Тоон гарын үсгээр (GSign) иргэний мэдээллийг баталгаажуулна. Утасны дугаараа оруулан GSign апп дээр PIN кодоор баталгаажуулна уу.</p>
  <p class="sub">MSSP ETSI TS 102 204 протоколоор ажиллана.</p>

  <div class="sign-form">
    <label class="form-label">Утасны дугаар</label>
    <div class="phone-row">
      <span class="phone-prefix">+976</span>
      <input type="text" id="phone" class="phone-input" placeholder="99112233" maxlength="8" autocomplete="off">
    </div>
    <button id="signBtn" class="sign-btn" onclick="doSign()">
      G-Sign Verify
    </button>
    <p class="sign-hint">GSign апп дээр PIN оруулах хүсэлт илгээгдэнэ (60 сек хүлээнэ)</p>
    <div id="status" class="status"></div>
  </div>

  <div id="result" class="result">
    <div class="result-card">
      <div class="result-header"><h3>Иргэний мэдээлэл амжилттай авлаа</h3></div>
      <div class="result-body" id="resultBody"></div>
      <div class="result-json"><pre id="resultJSON"></pre></div>
    </div>
  </div>
</div>

<div class="features">
  <div class="feature">
    <div class="feature-icon purple">&#128274;</div>
    <h3>Клауд тоон гарын үсэг</h3>
    <p>GSign апп-аар 4 оронтой PIN кодоор баталгаажуулна. Сертификат клауд дээр хадгалагдана.</p>
  </div>
  <div class="feature">
    <div class="feature-icon green">&#9989;</div>
    <h3>Сертификатаас мэдээлэл</h3>
    <p>Тоон гарын үсгийн сертификатын SubjectDN-ээс регистрийн дугаар, нэр зэргийг задлана.</p>
  </div>
  <div class="feature">
    <div class="feature-icon amber">&#9889;</div>
    <h3>3-р тал холболт</h3>
    <p>callback_url параметрээр иргэний мэдээллийг таны системд буцаана.</p>
  </div>
</div>

<div class="footer">
  G-Sign Gateway &middot; <a href="https://gerege.mn">gerege.mn</a>
</div>

<script>
const labels={reg_no:"Регистрийн дугаар",serialnumber:"SerialNumber",given_name:"Нэр",family_name:"Овог",surname:"Ургийн овог",cn:"CN (Common Name)",country:"Улс",locality:"Locality",state:"State",organization:"Байгууллага",ou:"Organizational Unit",not_before:"Серт эхлэх",not_after:"Серт дуусах",is_valid:"Хүчинтэй эсэх",signed_data:"Signed Data",subject_dn:"Subject DN (raw)",issuer_dn:"Issuer DN (raw)",cert_serial:"Серт serial"};

async function doSign(){
  const phone=document.getElementById("phone").value.trim();
  if(!phone||phone.length<8){alert("Утасны дугаараа оруулна уу");return}
  const btn=document.getElementById("signBtn");
  const st=document.getElementById("status");
  const res=document.getElementById("result");
  btn.disabled=true;btn.textContent="GSign апп-д хүсэлт илгээгдлээ...";
  st.className="status loading";st.style.display="block";
  st.textContent="GSign апп дээрээ PIN оруулна уу...";
  res.classList.remove("show");
  try{
    const r=await fetch("/sign",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({phoneNo:phone})});
    const data=await r.json();
    if(!r.ok){throw new Error(data.error||"Алдаа гарлаа")}
    st.className="status success";st.textContent="Амжилттай!";
    const citizen=data.citizen||{};
    let rows="";
    // Show ALL fields
    Object.keys(citizen).sort().forEach(k=>{
      if(citizen[k]){
        const label=labels[k]||k;
        const val=citizen[k].length>80?citizen[k].substring(0,80)+"...":citizen[k];
        rows+='<div class="result-row"><div class="result-label">'+label+'</div><div class="result-value">'+val+'</div></div>';
      }
    });
    document.getElementById("resultBody").innerHTML=rows;
    document.getElementById("resultJSON").textContent=JSON.stringify(citizen,null,2);
    res.classList.add("show");
    if(data.redirectUrl){setTimeout(()=>{window.location.href=data.redirectUrl},2000)}
  }catch(e){
    st.className="status error";st.textContent=e.message;
  }finally{
    btn.disabled=false;btn.textContent="G-Sign Verify";
  }
}

document.getElementById("phone").addEventListener("keydown",e=>{if(e.key==="Enter")doSign()});
</script>
</body>
</html>`

const verifyPage = `<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>G-Sign Verify</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0b1120;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{max-width:420px;width:100%%;margin:24px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:40px 32px;text-align:center}
.icon{width:56px;height:56px;background:linear-gradient(135deg,#7c3aed,#6d28d9);border-radius:14px;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;color:#fff;font-size:24px;font-weight:800}
h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:8px}
.sub{font-size:14px;color:#94a3b8;margin-bottom:24px}
.form-label{display:block;font-size:13px;color:#94a3b8;margin-bottom:6px;font-weight:500;text-align:left}
.phone-row{display:flex;gap:8px;margin-bottom:16px}
.phone-prefix{padding:14px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:12px;color:#94a3b8;font-size:15px;font-weight:600}
.phone-input{flex:1;padding:14px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:12px;color:#fff;font-size:15px;outline:none}
.phone-input:focus{border-color:#7c3aed}
.phone-input::placeholder{color:#475569}
.sign-btn{width:100%%;padding:16px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;font-weight:700;font-size:16px;border:none;border-radius:14px;cursor:pointer;transition:all .2s}
.sign-btn:hover{transform:translateY(-1px)}
.sign-btn:disabled{opacity:.6;cursor:not-allowed;transform:none}
.hint{margin-top:12px;font-size:12px;color:#475569}
.status{margin-top:16px;padding:14px;border-radius:10px;font-size:13px;display:none;text-align:center}
.status.loading{display:block;background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.2);color:#a78bfa}
.status.success{display:block;background:rgba(22,163,74,.1);border:1px solid rgba(22,163,74,.2);color:#4ade80}
.status.error{display:block;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#f87171}
</style>
</head>
<body>
<div class="card">
  <div class="icon">G</div>
  <h1>G-Sign Verify</h1>
  <p class="sub">Тоон гарын үсгээр иргэний мэдээлэл баталгаажуулна</p>
  <label class="form-label">Утасны дугаар</label>
  <div class="phone-row">
    <span class="phone-prefix">+976</span>
    <input type="text" id="phone" class="phone-input" placeholder="99112233" maxlength="8" autocomplete="off">
  </div>
  <button id="signBtn" class="sign-btn" onclick="doVerify()">G-Sign Verify</button>
  <p class="hint">GSign апп дээр PIN оруулах хүсэлт илгээгдэнэ</p>
  <div id="status" class="status"></div>
</div>
<script>
const callbackUrl="%s";
async function doVerify(){
  const phone=document.getElementById("phone").value.trim();
  if(!phone||phone.length<8){alert("Утасны дугаараа оруулна уу");return}
  const btn=document.getElementById("signBtn");
  const st=document.getElementById("status");
  btn.disabled=true;btn.textContent="GSign апп-д хүсэлт илгээгдлээ...";
  st.className="status loading";st.style.display="block";
  st.textContent="GSign апп дээрээ PIN оруулна уу...";
  try{
    const body={phoneNo:phone};
    if(callbackUrl)body.callbackUrl=callbackUrl;
    const r=await fetch("/sign",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error||"Алдаа");
    st.className="status success";st.textContent="Амжилттай!";
    if(data.redirectUrl){st.textContent="Амжилттай! Буцаж чиглүүлж байна...";setTimeout(()=>{window.location.href=data.redirectUrl},1000)}
    else{st.textContent="Амжилттай! Мэдээлэл: "+JSON.stringify(data.citizen)}
  }catch(e){
    st.className="status error";st.textContent=e.message;
  }finally{btn.disabled=false;btn.textContent="G-Sign Verify"}
}
document.getElementById("phone").addEventListener("keydown",e=>{if(e.key==="Enter")doVerify()});
</script>
</body>
</html>`
