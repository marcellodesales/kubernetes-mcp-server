package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/kubernetes-mcp-server/pkg/config"
	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/mcp"
)

const (
	tokenTypeClient      = "client"
	tokenTypeAuthRequest = "auth_request"
	tokenTypeAuthCode    = "auth_code"
	tokenTypeAccess      = "access"

	sealerAADPrefix = "kubernetes-mcp-server/bootstrap"
)

type Options struct {
	CfgState        *config.StaticConfigState
	McpServer       *mcp.Server
	DynamicProvider *kubernetes.DynamicProvider
	ProviderBuilder func(ctx context.Context) (kubernetes.Provider, error)
	// Optional override used by tests.
	KubeconfigValidator func(ctx context.Context, kubeconfigPath string) (*ClusterFacts, error)
}

type Server struct {
	cfgState       *config.StaticConfigState
	mcpServer      *mcp.Server
	dyn            *kubernetes.DynamicProvider
	buildProv      func(ctx context.Context) (kubernetes.Provider, error)
	validate       func(ctx context.Context, kubeconfigPath string) (*ClusterFacts, error)
	sealer         *Sealer
	now            func() time.Time
	accessTokenTTL time.Duration

	configureMu sync.Mutex
}

func NewServer(opts Options) (*Server, error) {
	if opts.CfgState == nil {
		return nil, errors.New("CfgState is required")
	}
	if opts.McpServer == nil {
		return nil, errors.New("McpServer is required")
	}
	if opts.DynamicProvider == nil {
		return nil, errors.New("DynamicProvider is required")
	}
	if opts.ProviderBuilder == nil {
		return nil, errors.New("ProviderBuilder is required")
	}

	key, err := sealerKeyFromEnv()
	if err != nil {
		return nil, err
	}
	sealer, err := NewSealer(key, sealerAADPrefix)
	if err != nil {
		return nil, err
	}

	validate := opts.KubeconfigValidator
	if validate == nil {
		validate = func(ctx context.Context, kubeconfigPath string) (*ClusterFacts, error) {
			return ValidateKubeconfig(ctx, kubeconfigPath, 25)
		}
	}

	return &Server{
		cfgState:       opts.CfgState,
		mcpServer:      opts.McpServer,
		dyn:            opts.DynamicProvider,
		buildProv:      opts.ProviderBuilder,
		validate:       validate,
		sealer:         sealer,
		now:            time.Now,
		accessTokenTTL: durationEnv("MCP_AUTH_ACCESS_TTL", 10*time.Hour),
	}, nil
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

func sealerKeyFromEnv() ([]byte, error) {
	secret := strings.TrimSpace(os.Getenv("MCP_AUTH_SECRET"))
	if secret != "" {
		return ParseSealerKeyBase64URL(secret)
	}
	key := make([]byte, sealKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral auth key: %w", err)
	}
	// Log the generated secret so operators can capture it for persistence across restarts.
	// Set MCP_AUTH_SECRET=<value> to keep bearer tokens valid after a restart.
	klog.InfoS("MCP_AUTH_SECRET not set — generated ephemeral auth key",
		"MCP_AUTH_SECRET", base64.RawURLEncoding.EncodeToString(key),
	)
	return key, nil
}

// RegisterRoutes registers the internal OAuth and bootstrap UI endpoints.
// Call this once during HTTP server initialization.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", s.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/mcp/server-card.json", s.handleServerCard)

	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/kube/login", s.handleKubeLogin)
	mux.HandleFunc("/kube/preview", s.handleKubePreview)
}

// Protect enforces sealed-token bearer auth for protected endpoints (e.g. /mcp).
func (s *Server) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			withCORSHeaders(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			s.writeAuthChallenge(w, r, "missing_token")
			return
		}
		claims := accessToken{}
		if err := s.sealer.Unseal(tokenTypeAccess, token, &claims); err != nil {
			s.writeAuthChallenge(w, r, "invalid_token")
			return
		}
		if err := claims.validate(s.now()); err != nil {
			s.writeAuthChallenge(w, r, "invalid_token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) writeAuthChallenge(w http.ResponseWriter, r *http.Request, errorType string) {
	metaURL := s.baseURL(r) + "/.well-known/oauth-protected-resource/mcp"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="Kubernetes MCP Server", resource_metadata="%s", error="%s"`, metaURL, errorType))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("Unauthorized"))
}

func bearerToken(header string) (string, bool) {
	if header == "" || !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	return t, t != ""
}

func (s *Server) baseURL(r *http.Request) string {
	cfg := s.cfgState.Load()
	if cfg.ServerURL != "" {
		return strings.TrimSuffix(cfg.ServerURL, "/")
	}
	scheme := "https"
	host := r.Host
	if cfg.TrustProxyHeaders {
		if r.TLS == nil && !strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "http"
		}
		if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
			host = fwdHost
		}
	} else {
		if r.TLS == nil {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func (s *Server) kubeconfigPath() string {
	cfg := s.cfgState.Load()
	if cfg.KubeConfig != "" {
		return cfg.KubeConfig
	}
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return filepath.Join("/", ".kube", "config")
	}
	return filepath.Join(h, ".kube", "config")
}

type tokenBase struct {
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

func newTokenBase(now time.Time, ttl time.Duration) tokenBase {
	return tokenBase{Iat: now.Unix(), Exp: now.Add(ttl).Unix()}
}

func (b tokenBase) validate(now time.Time) error {
	if now.Unix() > b.Exp {
		return errors.New("token expired")
	}
	return nil
}

type clientRegistration struct {
	tokenBase
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
}

type authRequest struct {
	tokenBase

	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state,omitempty"`
	Scope               string `json:"scope,omitempty"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type authCode struct {
	tokenBase

	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope,omitempty"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type accessToken struct {
	tokenBase

	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		withCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.cfgState.Load()
	base := s.baseURL(r)

	meta := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	if len(cfg.OAuthScopes) > 0 {
		meta["scopes_supported"] = cfg.OAuthScopes
	}
	if !cfg.DisableDynamicClientRegistration {
		meta["registration_endpoint"] = base + "/register"
	}

	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		withCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.cfgState.Load()
	base := s.baseURL(r)
	meta := map[string]any{
		"resource":                 base + "/mcp",
		"authorization_servers":    []string{base},
		"bearer_methods_supported": []string{"header"},
	}
	if len(cfg.OAuthScopes) > 0 {
		meta["scopes_supported"] = cfg.OAuthScopes
	}

	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleServerCard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		withCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base := s.baseURL(r)
	card := map[string]any{
		"name":         "kubernetes-mcp-server",
		"mcp_endpoint": base + "/mcp",
		"sse_endpoint": base + "/sse",
		"login_url":    base + "/kube/login",
	}
	writeJSON(w, http.StatusOK, card)
}

type registerRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
}

type registerResponse struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name,omitempty"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		withCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfgState.Load().DisableDynamicClientRegistration {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}
	for i := range req.RedirectURIs {
		if err := validateRedirectURI(req.RedirectURIs[i]); err != nil {
			http.Error(w, fmt.Sprintf("invalid redirect_uri: %v", err), http.StatusBadRequest)
			return
		}
	}

	reg := clientRegistration{
		tokenBase:    newTokenBase(s.now(), 24*time.Hour),
		RedirectURIs: append([]string(nil), req.RedirectURIs...),
		ClientName:   req.ClientName,
	}
	clientID, err := s.sealer.Seal(tokenTypeClient, &reg)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp := registerResponse{
		ClientID:                clientID,
		RedirectURIs:            reg.RedirectURIs,
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		ClientName:              reg.ClientName,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	// MCP desktop clients commonly register private-use callback schemes
	// (for example warp://...) instead of only http(s). Keep this aligned with
	// the other Viasat MCP servers: require an absolute URI with scheme+host,
	// then enforce exact redirect_uri matching during authorize/token exchange.
	if u.Scheme == "" {
		return errors.New("missing scheme")
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	if u.Fragment != "" {
		return errors.New("fragment not allowed")
	}
	return nil
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "response_type must be 'code'", http.StatusBadRequest)
		return
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	scope := q.Get("scope")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	if clientID == "" || redirectURI == "" {
		http.Error(w, "client_id and redirect_uri are required", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "PKCE code_challenge and code_challenge_method=S256 are required", http.StatusBadRequest)
		return
	}

	reg, err := s.parseClientRegistration(clientID)
	if err != nil {
		// The client_id is a sealed registration token. Unsealing fails when the
		// server's signing key (MCP_AUTH_SECRET) was rotated/regenerated since the
		// client registered, or when the 24h registration TTL has lapsed. Show the
		// user a recoverable message instead of a bare "invalid client_id".
		s.renderAuthError(w, r, http.StatusBadRequest, authErrorView{
			Title:   "Reconnect required",
			Summary: "This server could not verify your client registration.",
			Details: []template.HTML{
				`Your MCP client authorized here before, but the credential it saved (its OAuth <code>client_id</code>) can no longer be verified by this server.`,
				`The usual cause is that the server restarted or its signing key (<code>MCP_AUTH_SECRET</code>) was rotated, which invalidates every previously issued registration. Client registrations also expire 24 hours after they are created.`,
			},
			Steps: reconnectSteps,
		})
		return
	}
	if !contains(reg.RedirectURIs, redirectURI) {
		s.renderAuthError(w, r, http.StatusBadRequest, authErrorView{
			Title:   "Redirect address not recognized",
			Summary: "The redirect_uri in this request is not registered for your client.",
			Details: []template.HTML{
				`Your MCP client asked to be redirected to an address that was not part of its original registration. For security this server only redirects to addresses a client registered up front.`,
				`This usually means the client's saved registration is stale. Reconnecting re-registers the current redirect address.`,
			},
			Steps: reconnectSteps,
		})
		return
	}

	areq := authRequest{
		tokenBase:           newTokenBase(s.now(), 10*time.Minute),
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	sealed, err := s.sealer.Seal(tokenTypeAuthRequest, &areq)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	loginURL := "/kube/login?request=" + url.QueryEscape(sealed)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func redirectWithCode(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Server) parseClientRegistration(clientID string) (*clientRegistration, error) {
	reg := clientRegistration{}
	if err := s.sealer.Unseal(tokenTypeClient, clientID, &reg); err != nil {
		return nil, err
	}
	if err := reg.validate(s.now()); err != nil {
		return nil, err
	}
	if len(reg.RedirectURIs) == 0 {
		return nil, errors.New("no redirect_uris")
	}
	return &reg, nil
}

func (s *Server) issueAuthCode(code authCode) (string, error) {
	return s.sealer.Seal(tokenTypeAuthCode, &code)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		withCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form body", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}

	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	if clientID == "" || redirectURI == "" || code == "" || verifier == "" {
		http.Error(w, "client_id, redirect_uri, code, and code_verifier are required", http.StatusBadRequest)
		return
	}

	reg, err := s.parseClientRegistration(clientID)
	if err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if !contains(reg.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri is not registered for client", http.StatusBadRequest)
		return
	}

	ac := authCode{}
	if err := s.sealer.Unseal(tokenTypeAuthCode, code, &ac); err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if err := ac.validate(s.now()); err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if ac.CodeChallengeMethod != "S256" {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if err := VerifyPKCES256(ac.CodeChallenge, verifier); err != nil {
		http.Error(w, "invalid code_verifier", http.StatusBadRequest)
		return
	}

	at := accessToken{
		tokenBase: newTokenBase(s.now(), s.accessTokenTTL),
		ClientID:  clientID,
		Scope:     ac.Scope,
	}
	access, err := s.sealer.Seal(tokenTypeAccess, &at)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	resp := tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       ac.Scope,
	}
	writeJSON(w, http.StatusOK, resp)
}

type kubeLoginView struct {
	HasExisting  bool
	ExistingPath string
	DefaultMode  string
	RequestToken string
	Error        string
	Pasted       string
}

var kubeLoginTemplate = template.Must(template.New("kube-login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Kubernetes MCP Server — Bootstrap</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#f5f5f5; margin:0; padding:0; }
    .card { max-width:760px; margin:7vh auto; background:#fff; padding:24px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    h1 { margin:0 0 8px 0; font-size:20px; }
    h2 { margin:0 0 10px 0; font-size:16px; }
    h3 { margin:12px 0 8px 0; font-size:14px; }
    p { margin:0 0 16px 0; color:#555; font-size:14px; line-height:1.4; }
    label { display:block; font-weight:600; font-size:13px; margin:12px 0 6px; }
    input, textarea { width:100%; padding:10px 12px; border:1px solid #ddd; border-radius:8px; font-size:14px; box-sizing:border-box; }
    input[type="radio"] { width:auto; margin:0 8px 0 0; accent-color:#0052cc; }
    textarea { min-height:220px; resize:vertical; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; line-height:1.35; }
    button { width:100%; margin-top:16px; padding:10px 12px; border:0; border-radius:8px; background:#0052cc; color:#fff; font-weight:700; font-size:14px; cursor:pointer; }
    button:hover { background:#0043a8; }
    .section { border:1px solid #e6e6e6; border-radius:10px; padding:14px; margin:12px 0; }
    .err { background:#fdecea; border:1px solid #f5c6cb; color:#7a1c1c; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; white-space:pre-wrap; }
    .success { background:#e7f7ed; border:1px solid #b7ebc6; color:#0f5132; padding:10px 12px; border-radius:8px; margin-bottom:12px; font-size:13px; }
    .info { background:#eef4ff; border:1px solid #cfe0ff; color:#1f3b7a; padding:10px 12px; border-radius:8px; margin:0 0 12px 0; font-size:13px; }
    .note { background:#fff8e1; border-left:4px solid #ff8f00; padding:10px 12px; border-radius:8px; margin-top:12px; font-size:13px; color:#555; }
    .muted { color:#666; font-size:12px; }
    .radio-row { display:flex; align-items:flex-start; gap:8px; margin:10px 0; }
    .radio-row label { margin:0; display:inline; }
    .dropzone { border:2px dashed #cfe0ff; border-radius:10px; padding:14px; margin:12px 0; background:#f8fbff; color:#1f3b7a; text-align:center; font-size:13px; }
    .dropzone.dragging { border-color:#0052cc; background:#eef4ff; }
    .invalid-input { border-color:#dc3545 !important; box-shadow:0 0 0 2px rgba(220,53,69,0.12); }
    .preview { margin-top:12px; }
    .hidden { display:none; }
    .steps { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; margin:12px 0; }
    .step { border:1px solid #e6e6e6; border-radius:10px; padding:10px 12px; background:#fff; color:#666; font-size:13px; font-weight:700; }
    button.step { width:100%; margin:0; text-align:left; cursor:pointer; }
    button.step:hover { border-color:#cfe0ff; background:#f8fbff; }
    .step.active { border-color:#cfe0ff; background:#eef4ff; color:#1f3b7a; }
    .step.done { border-color:#b7ebc6; background:#e7f7ed; color:#0f5132; }
    .step.error { border-color:#f5c6cb; background:#fdecea; color:#7a1c1c; }
    .step small { display:block; margin-top:2px; font-weight:500; font-size:11px; color:inherit; opacity:0.82; }
    .step-content { margin-top:12px; }
    .config-header { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; border:1px solid #e6e6e6; border-radius:10px; padding:14px; margin:12px 0; }
    .chip { display:inline-block; padding:3px 8px; border-radius:999px; background:#eef4ff; color:#1f3b7a; font-size:12px; font-weight:700; white-space:nowrap; }
    .chip.ok { background:#e7f7ed; color:#0f5132; }
    .chip.warn { background:#fff8e1; color:#7a5200; }
    .cluster-grid { display:grid; grid-template-columns:1fr; gap:12px; margin-top:12px; }
    .cluster-card { border:1px solid #e6e6e6; border-radius:12px; padding:16px; background:#fff; }
    .cluster-card.current { border-color:#7bd88f; background:linear-gradient(180deg, #fbfffc 0%, #ffffff 100%); box-shadow:0 0 0 3px rgba(15,81,50,0.08); }
    .cluster-card h3 { margin:0 0 10px 0; font-size:16px; }
    .cluster-heading { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:8px; }
    .nested { border-top:1px solid #f0f0f0; margin-top:12px; padding-top:10px; }
    .nested h4 { margin:0 0 8px 0; font-size:13px; color:#333; }
    .actions { display:flex; gap:10px; margin-top:14px; }
    .actions button { margin-top:0; }
    .meta-row { font-size:13px; margin:6px 0; color:#333; overflow-wrap:anywhere; }
    .meta-label { font-weight:600; margin-right:6px; }
    .source-panel pre { max-height:360px; overflow:auto; padding:12px; border-radius:8px; background:#1f2937; color:#e5e7eb; font-size:12px; line-height:1.4; white-space:pre-wrap; }
    button:disabled { background:#b8c2d6; cursor:not-allowed; }
    button.loading { display:flex; align-items:center; justify-content:center; gap:8px; }
    .spinner { display:inline-block; width:13px; height:13px; border:2px solid rgba(255,255,255,0.45); border-top-color:#fff; border-radius:50%; animation:spin .8s linear infinite; }
    button.secondary { background:#f1f1f1; color:#333; border:1px solid #ddd; }
    button.secondary:hover { background:#e6e6e6; }
    code { background:#f1f1f1; padding:1px 4px; border-radius:4px; }
    @keyframes spin { to { transform:rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <h1>Kubernetes MCP Server</h1>
    <p>Connect this MCP server by validating a kubeconfig. The server will not connect to Kubernetes until this step succeeds.</p>
    <div class="info">
      🔐 Bootstrap mode protects <code>/mcp</code> with internal OAuth and keeps all auth state sealed into short-lived tokens.
    </div>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form id="kubeForm" method="post" action="/kube/login" enctype="multipart/form-data" autocomplete="off">
      <div class="steps">
        <button id="stepSource" type="button" class="step active">🔎 1. Source validation<small>Paste, drop, upload, or use existing</small></button>
        <button id="stepReview" type="button" class="step">⏳ 2. Review target<small>Confirm cluster URL and user</small></button>
        <button id="stepCurrent" type="button" class="step">⏳ 3. Current state<small>Shown after confirmation</small></button>
      </div>

      <div id="sourceStepPanel" class="step-content">
        <div id="sourceControls" class="section">
          <h2>🔑 Kubeconfig source</h2>
          <p class="muted">Choose an existing kubeconfig, paste YAML, or upload a file. Pasted/uploaded content is persisted with owner-only permissions only after you enable access.</p>
          <div id="dropZone" class="dropzone">
            🧲 Drag and drop a kubeconfig YAML/JSON file here, or paste it below.
          </div>
        {{if .HasExisting}}
          <div class="radio-row">
            <input id="mode_existing" type="radio" name="mode" value="existing" autocomplete="off" {{if eq .DefaultMode "existing"}}checked{{end}} />
            <label for="mode_existing">📁 Use existing kubeconfig<br/><span class="muted"><code>{{.ExistingPath}}</code></span></label>
          </div>
        {{end}}
          <div class="radio-row">
            <input id="mode_paste" type="radio" name="mode" value="paste" autocomplete="off" {{if eq .DefaultMode "paste"}}checked{{end}} />
            <label for="mode_paste">📋 Paste kubeconfig YAML</label>
          </div>
          <textarea id="kubeconfigPaste" name="kubeconfig_paste" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" placeholder="apiVersion: v1&#10;clusters: ...">{{.Pasted}}</textarea>

          <div class="radio-row">
            <input id="mode_upload" type="radio" name="mode" value="upload" autocomplete="off" {{if eq .DefaultMode "upload"}}checked{{end}} />
            <label for="mode_upload">📎 Upload kubeconfig file</label>
          </div>
          <input id="kubeconfigUpload" type="file" name="kubeconfig_upload" autocomplete="off" accept=".yaml,.yml,.json,.conf,.config,text/yaml,application/yaml,application/json" />
        </div>
        <div id="previewStatus" class="info">
          🧪 Paste, drop, upload, or select an existing kubeconfig to preview it before enabling access.
        </div>
        <div id="sourcePanel" class="source-panel hidden">
          <pre id="sourceCode"></pre>
          <button id="backButton" type="button" class="secondary">⬅️ Back to target review</button>
        </div>
      </div>
      <div id="reviewStepPanel" class="step-content hidden">
        <div id="configHeader" class="config-header"></div>
        <div id="clusterCards" class="cluster-grid"></div>
        <div class="actions">
          <button id="changeSourceButton" type="button" class="secondary">⬅️ Change kubeconfig</button>
          <button id="detailsButton" type="button" class="secondary">📄 Show source details</button>
        </div>
        <input type="hidden" name="request" value="{{.RequestToken}}" />
        <button id="enableButton" type="submit" disabled>🔒 Validate kubeconfig preview first</button>
      </div>

    </form>

    <div class="note">
      Treat kubeconfig contents as sensitive. Source details are shown only in this browser so you can inspect parse errors or confirm the file before enabling access.
    </div>
  </div>
  <script>
  (function () {
    var form = document.getElementById('kubeForm');
    var paste = document.getElementById('kubeconfigPaste');
    var upload = document.getElementById('kubeconfigUpload');
    var dropZone = document.getElementById('dropZone');
    var previewStatus = document.getElementById('previewStatus');
    var sourceStepPanel = document.getElementById('sourceStepPanel');
    var reviewStepPanel = document.getElementById('reviewStepPanel');
    var stepSource = document.getElementById('stepSource');
    var stepReview = document.getElementById('stepReview');
    var stepCurrent = document.getElementById('stepCurrent');
    var sourceControls = document.getElementById('sourceControls');
    var sourcePanel = document.getElementById('sourcePanel');
    var sourceCode = document.getElementById('sourceCode');
    var configHeader = document.getElementById('configHeader');
    var clusterCards = document.getElementById('clusterCards');
    var detailsButton = document.getElementById('detailsButton');
    var backButton = document.getElementById('backButton');
    var changeSourceButton = document.getElementById('changeSourceButton');
    var enableButton = document.getElementById('enableButton');
    var debounceTimer;
    var lastSource = '';
    var lastPreviewValid = false;
    var lastPreview = null;

    function escapeHtml(value) {
      return String(value || '').replace(/[&<>"']/g, function (ch) {
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
      });
    }

    function selectedMode() {
      var checked = form.querySelector('input[name="mode"]:checked');
      return checked ? checked.value : 'paste';
    }

    function setMode(mode) {
      var input = form.querySelector('input[name="mode"][value="' + mode + '"]');
      if (input) {
        input.checked = true;
      }
    }

    function setUploadEnabled(enabled) {
      upload.disabled = !enabled;
    }
    function setStepCard(el, state, icon, title, detail) {
      el.className = state === 'pending' ? 'step' : 'step ' + state;
      el.innerHTML = icon + ' ' + title + '<small>' + detail + '</small>';
      el.setAttribute('aria-current', state === 'active' ? 'step' : 'false');
    }

    function setStep(step) {
      if (step === 'review') {
        sourceStepPanel.classList.add('hidden');
        reviewStepPanel.classList.remove('hidden');
        sourcePanel.classList.add('hidden');
        sourceControls.classList.remove('hidden');
        setUploadEnabled(false);
        setStepCard(stepSource, 'done', '✅', '1. Source validation', 'Kubeconfig parsed');
        setStepCard(stepReview, 'active', '👀', '2. Review target', 'Confirm cluster URL and user');
        setStepCard(stepCurrent, 'pending', '⏳', '3. Current state', 'Shown after confirmation');
      } else {
        reviewStepPanel.classList.add('hidden');
        sourceStepPanel.classList.remove('hidden');
        setUploadEnabled(true);
        setStepCard(stepSource, 'active', '🔎', '1. Source validation', 'Paste, drop, upload, or use existing');
        setStepCard(stepReview, lastPreviewValid ? 'done' : 'pending', lastPreviewValid ? '✅' : '⏳', '2. Review target', lastPreviewValid ? 'Preview completed' : 'Confirm cluster URL and user');
        setStepCard(stepCurrent, 'pending', '⏳', '3. Current state', 'Shown after confirmation');
      }
    }

    function setEnable(valid) {
      lastPreviewValid = !!valid;
      enableButton.disabled = !lastPreviewValid;
      enableButton.textContent = lastPreviewValid ? '🚀 Enable Kubernetes Access' : '🔒 Validate kubeconfig preview first';
    }

    function setStatus(kind, html) {
      previewStatus.className = kind;
      previewStatus.innerHTML = html;
    }

    function resetPreview(message) {
      lastPreview = null;
      setEnable(false);
      setStep('source');
      paste.classList.remove('invalid-input');
      dropZone.classList.remove('invalid-input');
      sourceControls.classList.remove('hidden');
      configHeader.innerHTML = '';
      clusterCards.innerHTML = '';
      setStatus('info', message || '🧪 Paste, drop, upload, or select an existing kubeconfig to validate it before review.');
    }

    function showSource(show) {
      if (show) {
        setStep('source');
        sourceControls.classList.add('hidden');
        sourcePanel.classList.remove('hidden');
        sourceCode.textContent = lastSource || 'Source is not displayed for the existing kubeconfig path.';
      } else {
        sourcePanel.classList.add('hidden');
        sourceControls.classList.remove('hidden');
        if (lastPreviewValid) {
          setStep('review');
        }
      }
    }

    function renderError(message, revealSource) {
      lastPreview = null;
      setEnable(false);
      setStep('source');
      configHeader.innerHTML = '';
      clusterCards.innerHTML = '';
      paste.classList.add('invalid-input');
      dropZone.classList.add('invalid-input');
      sourceControls.classList.remove('hidden');
      setStepCard(stepSource, 'error', '❌', '1. Source validation', 'Fix the source and validate again');
      setStepCard(stepReview, 'pending', '⏳', '2. Review target', 'Confirm cluster URL and user');
      setStepCard(stepCurrent, 'pending', '⏳', '3. Current state', 'Shown after confirmation');
      setStatus('err', '❌ Kubeconfig source validation failed: ' + escapeHtml(message));
      if (revealSource) {
        sourcePanel.classList.remove('hidden');
        sourceCode.textContent = lastSource || '';
      } else {
        sourcePanel.classList.add('hidden');
      }
    }

    function certificateLine(cert) {
      if (!cert) {
        return '<span class="muted">No certificate info</span>';
      }
      var bits = [];
      if (cert.summary) {
        bits.push(escapeHtml(cert.summary));
      }
      if (cert.expired) {
        bits.push('<span class="chip warn">expired</span>');
      } else if (cert.expiresInDays) {
        bits.push('<span class="chip">expires in ' + escapeHtml(cert.expiresInDays) + ' days</span>');
      }
      if (cert.subjects && cert.subjects.length) {
        bits.push('<div class="muted">Subject: ' + escapeHtml(cert.subjects[0]) + '</div>');
      }
      if (cert.error) {
        bits.push('<span class="chip warn">' + escapeHtml(cert.error) + '</span>');
      }
      return bits.join(' ');
    }

    function usersForCluster(preview, clusterName) {
      var userNames = {};
      (preview.contexts || []).forEach(function (ctx) {
        if (ctx.cluster === clusterName && ctx.user) {
          userNames[ctx.user] = true;
        }
      });
      return (preview.users || []).filter(function (user) { return !!userNames[user.name]; });
    }

    function contextsForCluster(preview, clusterName) {
      return (preview.contexts || []).filter(function (ctx) { return ctx.cluster === clusterName; });
    }

    function renderRelatedUsers(users) {
      if (!users.length) {
        return '<div class="muted">No user is referenced by this cluster context.</div>';
      }
      return users.map(function (user) {
        var token = user.tokenPreview ? '<div class="meta-row"><span class="meta-label">Token</span><code>' + escapeHtml(user.tokenPreview) + '</code></div>' : '';
        var exec = user.execCommand ? '<div class="meta-row"><span class="meta-label">Exec</span><code>' + escapeHtml(user.execCommand) + '</code></div>' : '';
        var tokenFile = user.tokenFile ? '<div class="meta-row"><span class="meta-label">Token file</span><code>' + escapeHtml(user.tokenFile) + '</code></div>' : '';
        var cert = user.hasClientCertificate ? '<span class="chip">client certificate</span> ' : '';
        var key = user.hasClientKey ? '<span class="chip">client key</span>' : '';
        return '<div class="meta-row"><span class="meta-label">👤 User</span><code>' + escapeHtml(user.name) + '</code> <span class="chip">' + escapeHtml(user.authMethod) + '</span></div>' + token + tokenFile + exec + '<div class="meta-row">' + cert + key + '</div>';
      }).join('');
    }

    function renderRelatedContexts(contexts) {
      if (!contexts.length) {
        return '<div class="muted">No contexts reference this cluster.</div>';
      }
      return contexts.map(function (ctx) {
        var current = ctx.current ? ' <span class="chip ok">✅ default</span>' : '';
        var ns = ctx.namespace ? ' namespace <code>' + escapeHtml(ctx.namespace) + '</code>' : '';
        return '<div class="meta-row"><span class="meta-label">🧭 Context</span><code>' + escapeHtml(ctx.name) + '</code>' + current + ns + '</div>';
      }).join('');
    }

    function renderClusters(preview) {
      var clusters = preview.clusters || [];
      if (!clusters.length) {
        clusterCards.innerHTML = '<div class="cluster-card"><h3>🖥️ No clusters</h3><div class="muted">No clusters were found in this kubeconfig.</div></div>';
        return;
      }
      clusterCards.innerHTML = clusters.map(function (cluster) {
        var current = cluster.current ? '<span class="chip ok">✅ current</span>' : '';
        var contexts = contextsForCluster(preview, cluster.name);
        var users = usersForCluster(preview, cluster.name);
        return '<div class="cluster-card ' + (cluster.current ? 'current' : '') + '">' +
          '<div class="cluster-heading"><h3>🖥️ ' + escapeHtml(cluster.name) + '</h3>' + current + '</div>' +
          '<div class="meta-row"><span class="meta-label">URL</span><code>' + escapeHtml(cluster.server) + '</code></div>' +
          '<div class="meta-row"><span class="meta-label">Host</span><code>' + escapeHtml(cluster.host || 'n/a') + '</code></div>' +
          '<div class="meta-row"><span class="meta-label">Certificate</span>' + certificateLine(cluster.certificate) + '</div>' +
          '<div class="nested"><h4>Related identity</h4>' + renderRelatedUsers(users) + '</div>' +
          '<div class="nested"><h4>Context mapping</h4>' + renderRelatedContexts(contexts) + '</div>' +
          '</div>';
      }).join('');
    }

    function renderPreview(preview) {
      lastPreview = preview;
      paste.classList.remove('invalid-input');
      dropZone.classList.remove('invalid-input');
      setEnable(true);
      setStatus('success', '✅ Source is valid ' + escapeHtml(preview.format || 'yaml') + '. Review the target cluster before connecting.');
      configHeader.innerHTML =
        '<div><strong>☸️ ' + escapeHtml(preview.kind || 'Config') + ' object</strong>' +
        '<div class="meta-row"><span class="meta-label">apiVersion</span><code>' + escapeHtml(preview.apiVersion || 'v1') + '</code></div>' +
        '<div class="meta-row"><span class="meta-label">current-context</span><code>' + escapeHtml(preview.currentContext || 'n/a') + '</code></div></div>' +
        '<span class="chip ok">✅ valid</span>';
      renderClusters(preview);
      setStep('review');
    }

    async function preview(mode, source) {
      try {
        setEnable(false);
        setStatus('info', '🔎 Validating kubeconfig source…');
        var response = await fetch('/kube/preview', {
          method: 'POST',
          cache: 'no-store',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({mode: mode, kubeconfig: source || ''})
        });
        var result = await response.json();
        if (!result.valid) {
          renderError(result.error || 'invalid kubeconfig', mode !== 'existing');
          return;
        }
        renderPreview(result);
      } catch (err) {
        renderError(err && err.message ? err.message : String(err), mode !== 'existing');
      }
    }

    function previewCurrentInput() {
      var mode = selectedMode();
      if (mode === 'existing') {
        lastSource = '';
        preview('existing', '');
        return;
      }
      lastSource = paste.value;
      if (!lastSource.trim()) {
        resetPreview('🧪 Paste, drop, or upload a kubeconfig YAML/JSON file to validate it.');
        return;
      }
      preview(mode, lastSource);
    }

    function schedulePreview() {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(previewCurrentInput, 350);
    }

    function readFile(file) {
      if (!file) {
        return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        setMode('paste');
        paste.value = String(reader.result || '');
        lastSource = paste.value;
        preview('paste', lastSource);
      };
      reader.onerror = function () {
        renderError('failed to read dropped/uploaded file', true);
      };
      reader.readAsText(file);
    }

    paste.addEventListener('input', function () {
      setMode('paste');
      schedulePreview();
    });
    paste.addEventListener('paste', function () {
      setMode('paste');
      setTimeout(previewCurrentInput, 0);
    });
    upload.addEventListener('change', function () {
      readFile(upload.files && upload.files[0]);
    });
    form.querySelectorAll('input[name="mode"]').forEach(function (input) {
      input.addEventListener('change', previewCurrentInput);
    });
    dropZone.addEventListener('dragover', function (event) {
      event.preventDefault();
      dropZone.classList.add('dragging');
    });
    dropZone.addEventListener('dragleave', function () {
      dropZone.classList.remove('dragging');
    });
    dropZone.addEventListener('drop', function (event) {
      event.preventDefault();
      dropZone.classList.remove('dragging');
      if (event.dataTransfer.files && event.dataTransfer.files.length > 0) {
        readFile(event.dataTransfer.files[0]);
        return;
      }
      var text = event.dataTransfer.getData('text/plain');
      if (text) {
        setMode('paste');
        paste.value = text;
        lastSource = text;
        preview('paste', text);
      }
    });
    detailsButton.addEventListener('click', function () {
      showSource(true);
    });
    backButton.addEventListener('click', function () {
      showSource(false);
    });

    stepSource.addEventListener('click', function () {
      sourcePanel.classList.add('hidden');
      sourceControls.classList.remove('hidden');
      setStep('source');
      setStatus(lastPreviewValid ? 'success' : 'info', lastPreviewValid ? '✅ Source is valid. You can edit it here or return to the review tab.' : '🧪 Paste, drop, upload, or select an existing kubeconfig to validate it before review.');
    });

    stepReview.addEventListener('click', function () {
      if (lastPreviewValid) {
        setStep('review');
        setStatus('success', '✅ Source is valid. Review the target cluster before connecting.');
        return;
      }
      setStep('source');
      setStatus('info', '⏳ Review target unlocks after source validation succeeds.');
    });

    stepCurrent.addEventListener('click', function () {
      if (lastPreviewValid) {
        setStep('review');
        setStatus('info', '⏳ Current state loads after you click Enable Kubernetes Access and the live cluster validation succeeds.');
        return;
      }
      setStep('source');
      setStatus('info', '⏳ Current state loads after source validation, target review, and confirmation.');
    });
    changeSourceButton.addEventListener('click', function () {
      setStep('source');
      sourcePanel.classList.add('hidden');
      sourceControls.classList.remove('hidden');
      setStatus(lastPreviewValid ? 'success' : 'info', lastPreviewValid ? '✅ Source is valid. Edit or replace it to re-validate.' : '🧪 Paste, drop, or upload a kubeconfig YAML/JSON file to validate it.');
    });
    form.addEventListener('submit', function (event) {
      if (!lastPreviewValid) {
        event.preventDefault();
        renderError('Source validation must pass before Kubernetes access can be enabled.', selectedMode() !== 'existing');
        return;
      }
      form.classList.add('submitting');
      enableButton.disabled = true;
      enableButton.classList.add('loading');
      enableButton.innerHTML = '<span class="spinner" aria-hidden="true"></span> Enabling Kubernetes Access…';
      setStatus('info', '⏳ Validating live cluster access and loading the current-state dashboard…');
    });
    function initializeFreshSourceState() {
      paste.value = '';
      upload.value = '';
      lastSource = '';
      lastPreviewValid = false;
      lastPreview = null;
      if (selectedMode() === 'existing') {
        setMode('paste');
      }
      resetPreview(document.querySelector('.err') ? '❌ Fix the source issue, then validate again.' : '🧪 Paste, drop, upload, or select an existing kubeconfig to validate it before review.');
      if (document.querySelector('.err')) {
        setStepCard(stepSource, 'error', '❌', '1. Source validation', 'Fix the source and validate again');
        setStatus('err', '❌ Fix the source issue, then validate again.');
      }
    }
    window.addEventListener('pageshow', function (event) {
      if (event.persisted) {
        initializeFreshSourceState();
      }
    });
    initializeFreshSourceState();
  })();
  </script>
</body>
</html>`))

var kubeSuccessTemplate = template.Must(template.New("kube-success").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Kubernetes MCP Server — Current State</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#f5f5f5; margin:0; padding:0; }
    .card { max-width:980px; margin:5vh auto; background:#fff; padding:24px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    h1 { margin:0 0 8px 0; font-size:20px; }
    h2 { margin:0 0 10px 0; font-size:16px; }
    h3 { margin:0 0 10px 0; font-size:15px; }
    p { margin:0 0 16px 0; color:#555; font-size:14px; line-height:1.4; }
    .steps { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; margin:12px 0 16px; }
    .step { border:1px solid #e6e6e6; border-radius:10px; padding:10px 12px; background:#fff; color:#666; font-size:13px; font-weight:700; }
    .step.active { border-color:#cfe0ff; background:#eef4ff; color:#1f3b7a; }
    .step.done { border-color:#b7ebc6; background:#e7f7ed; color:#0f5132; }
    .step small { display:block; margin-top:2px; font-weight:500; font-size:11px; color:inherit; opacity:0.82; }
    .connected { background:linear-gradient(135deg, #e7f7ed 0%, #f9fffb 100%); border:1px solid #b7ebc6; color:#0f5132; padding:14px; border-radius:12px; margin:14px 0; }
    .connected-head { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap; }
    .connected-title { font-size:16px; font-weight:800; margin-bottom:8px; }
    .chip { display:inline-block; padding:3px 8px; border-radius:999px; background:#eef4ff; color:#1f3b7a; font-size:12px; font-weight:700; white-space:nowrap; }
    .chip.ok { background:#0f5132; color:#fff; }
    .chip.soft { background:#e7f7ed; color:#0f5132; border:1px solid #b7ebc6; }
    .dashboard { display:grid; grid-template-columns:230px 1fr; gap:16px; margin-top:14px; }
    .menu { border:1px solid #e6e6e6; border-radius:12px; padding:10px; background:#fbfbfb; align-self:start; }
    .menu-title { font-size:12px; color:#555; font-weight:800; text-transform:uppercase; letter-spacing:.04em; margin:2px 0 8px; }
    .menu button { width:100%; text-align:left; margin:4px 0; padding:10px 12px; border:1px solid transparent; border-radius:10px; background:transparent; color:#333; font-weight:700; cursor:pointer; }
    .menu button:hover { background:#eef4ff; }
    .menu button.active { background:#0052cc; color:#fff; }
    .panel { border:1px solid #e6e6e6; border-radius:12px; padding:16px; background:#fff; min-height:260px; }
    .panel.hidden { display:none; }
    .panel-header { display:flex; justify-content:space-between; gap:10px; align-items:center; margin-bottom:8px; }
    .list { list-style:none; margin:10px 0 0; padding:0; display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:8px; }
    .list li { border:1px solid #f0f0f0; border-radius:10px; padding:9px 10px; font-size:13px; color:#333; background:#fcfcfc; overflow-wrap:anywhere; }
    .tools { grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); }
    .muted { color:#666; font-size:12px; }
    .warning { background:#fff8e1; border-left:4px solid #ff8f00; padding:10px 12px; border-radius:8px; margin:10px 0; font-size:13px; color:#555; }
    .info { background:#eef4ff; border:1px solid #cfe0ff; color:#1f3b7a; padding:10px 12px; border-radius:8px; margin:14px 0 0; font-size:13px; }
    .continue-action { display:block; text-align:center; text-decoration:none; margin-top:14px; padding:10px 12px; border-radius:8px; background:#0052cc; color:#fff; font-weight:700; font-size:14px; }
    .continue-action:hover { background:#0043a8; }
    .meta-row { font-size:13px; margin:6px 0; color:#173b22; overflow-wrap:anywhere; }
    .meta-label { font-weight:700; margin-right:6px; }
    code { background:rgba(0,0,0,0.06); padding:1px 4px; border-radius:4px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
    @media (max-width: 780px) {
      .card { margin:0; border-radius:0; min-height:100vh; }
      .steps { grid-template-columns:1fr; }
      .dashboard { grid-template-columns:1fr; }
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Kubernetes MCP Server</h1>
    <p>Kubernetes access is enabled. Review the connected cluster inventory and the MCP tools now available to your client.</p>

    <div class="steps">
      <div class="step done">✅ 1. Source validation<small>Kubeconfig parsed</small></div>
      <div class="step done">✅ 2. Review target<small>Cluster confirmed</small></div>
      <div class="step active">✅ 3. Current state<small>Live API inventory</small></div>
    </div>

    <div class="connected">
      <div class="connected-head">
        <div>
          <div class="connected-title">✅ Kubernetes access enabled</div>
          <div class="meta-row"><span class="meta-label">URL</span><code>{{.APIServerURL}}</code></div>
          <div class="meta-row"><span class="meta-label">Host</span><code>{{if .APIHost}}{{.APIHost}}{{else}}n/a{{end}}</code></div>
        </div>
        <div>
          {{if .ClusterVersion}}<span class="chip ok">{{.ClusterVersion}}</span>{{end}}
          <span class="chip soft">context: {{.ContextName}}</span>
        </div>
      </div>
    </div>

    {{range .InventoryWarnings}}
      <div class="warning">⚠️ {{.}}</div>
    {{end}}

    {{if .RedirectURL}}
      <div class="info">
        OAuth authorization is ready. Review the current state below, then continue back to your MCP client.
        <a class="continue-action" href="{{.RedirectURL}}">🚀 Continue to MCP client</a>
      </div>
    {{end}}

    <div class="dashboard">
      <nav class="menu" aria-label="Cluster inventory groups">
        <div class="menu-title">Group Menu (5)</div>
        <button type="button" class="active" data-panel="namespaces">📚 Namespaces ({{.NamespaceCount}})</button>
        <button type="button" data-panel="nodes">🖥️ Nodes ({{.NodeCount}})</button>
        <button type="button" data-panel="serviceaccounts">👤 Service Accounts ({{.ServiceAccountCount}})</button>
        <button type="button" data-panel="crds">🧩 CRDs ({{.CRDCount}})</button>
        <button type="button" data-panel="tools">🛠️ Tools ({{len .Tools}})</button>
      </nav>

      <main>
        <section id="panel-namespaces" class="panel">
          <div class="panel-header"><h2>📚 Namespaces</h2><span class="chip">{{.NamespaceCount}}</span></div>
          {{if gt .NamespaceCount (len .Namespaces)}}<p class="muted">Showing first {{len .Namespaces}} of {{.NamespaceCount}} namespaces.</p>{{end}}
          <ul class="list">
            {{range .Namespaces}}<li>📦 <code>{{.}}</code></li>{{else}}<li>No namespaces returned.</li>{{end}}
          </ul>
        </section>

        <section id="panel-nodes" class="panel hidden">
          <div class="panel-header"><h2>🖥️ Nodes</h2><span class="chip">{{.NodeCount}}</span></div>
          {{if gt .NodeCount (len .Nodes)}}<p class="muted">Showing first {{len .Nodes}} of {{.NodeCount}} nodes.</p>{{end}}
          <ul class="list">
            {{range .Nodes}}<li>🧭 <code>{{.}}</code></li>{{else}}<li>No nodes returned.</li>{{end}}
          </ul>
        </section>

        <section id="panel-serviceaccounts" class="panel hidden">
          <div class="panel-header"><h2>👤 Service Accounts</h2><span class="chip">{{.ServiceAccountCount}}</span></div>
          {{if gt .ServiceAccountCount (len .ServiceAccounts)}}<p class="muted">Showing first {{len .ServiceAccounts}} of {{.ServiceAccountCount}} service accounts.</p>{{end}}
          <ul class="list">
            {{range .ServiceAccounts}}<li>🔐 <code>{{.}}</code></li>{{else}}<li>No service accounts returned.</li>{{end}}
          </ul>
        </section>

        <section id="panel-crds" class="panel hidden">
          <div class="panel-header"><h2>🧩 Custom Resource Definitions</h2><span class="chip">{{.CRDCount}}</span></div>
          {{if gt .CRDCount (len .CRDs)}}<p class="muted">Showing first {{len .CRDs}} of {{.CRDCount}} CRDs.</p>{{end}}
          <ul class="list">
            {{range .CRDs}}<li>🧬 <code>{{.}}</code></li>{{else}}<li>No CRDs returned.</li>{{end}}
          </ul>
        </section>

        <section id="panel-tools" class="panel hidden">
          <div class="panel-header"><h2>🛠️ MCP Tools</h2><span class="chip">{{len .Tools}}</span></div>
          <p class="muted">These are the tools currently registered by the MCP server after kubeconfig bootstrap and configuration reload.</p>
          <ul class="list tools">
            {{range .Tools}}<li>⚙️ <code>{{.}}</code></li>{{else}}<li>No MCP tools are currently enabled.</li>{{end}}
          </ul>
        </section>
      </main>
    </div>

    <div class="info">
      It is safe to close this tab. Return to your MCP client and retry the connection or tool call.
    </div>
  </div>
  <script>
  (function () {
    var buttons = Array.from(document.querySelectorAll('.menu button[data-panel]'));
    var panels = Array.from(document.querySelectorAll('.panel'));
    buttons.forEach(function (button) {
      button.addEventListener('click', function () {
        var target = 'panel-' + button.getAttribute('data-panel');
        buttons.forEach(function (item) { item.classList.toggle('active', item === button); });
        panels.forEach(function (panel) { panel.classList.toggle('hidden', panel.id !== target); });
      });
    });
  })();
  </script>
</body>
</html>`))

// authErrorView backs authErrorTemplate. Its fields are developer-authored
// (never request data), so Details/Steps are template.HTML to allow inline
// <code> formatting without HTML-escaping.
type authErrorView struct {
	Title   string
	Summary string
	Details []template.HTML
	Steps   []template.HTML
}

// reconnectSteps is the standard remediation shown when a client's saved OAuth
// registration can no longer be honored (rotated signing key or expired
// registration). Reconnecting forces the client to register again.
var reconnectSteps = []template.HTML{
	`In your MCP client, remove or disconnect this server so it drops the stale saved credential. In Claude Code: <code>/mcp</code> &rarr; select this server &rarr; disconnect (or re-run <code>claude mcp add</code>).`,
	`Reconnect / re-add the server. The client will register again automatically and reopen this login page.`,
	`Complete the kubeconfig login when the browser opens — access is restored once validation succeeds.`,
}

// authErrorTemplate renders a browser-facing OAuth failure using the same card
// styling as the bootstrap login page. RFC 6749 §4.1.2.1 requires that when the
// client_id or redirect_uri is invalid we inform the user directly instead of
// redirecting to an untrusted URI — so these are HTML pages, not redirects.
var authErrorTemplate = template.Must(template.New("auth-error").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Kubernetes MCP Server — Reconnect required</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:#f5f5f5; margin:0; padding:0; }
    .card { max-width:640px; margin:7vh auto; background:#fff; padding:24px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
    h1 { margin:0 0 8px 0; font-size:20px; }
    h2 { margin:0 0 10px 0; font-size:15px; }
    p { margin:0 0 14px 0; color:#444; font-size:14px; line-height:1.5; }
    .err { background:#fdecea; border:1px solid #f5c6cb; color:#7a1c1c; padding:12px 14px; border-radius:8px; margin-bottom:16px; font-size:14px; line-height:1.5; }
    .section { border:1px solid #e6e6e6; border-radius:10px; padding:14px 16px; margin:14px 0; }
    .section ol { margin:8px 0 0; padding-left:20px; }
    .section li { margin:8px 0; font-size:14px; color:#333; line-height:1.5; }
    .note { background:#fff8e1; border-left:4px solid #ff8f00; padding:10px 12px; border-radius:8px; margin-top:14px; font-size:13px; color:#555; line-height:1.5; }
    code { background:#f1f1f1; padding:1px 5px; border-radius:4px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:0.92em; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Kubernetes MCP Server</h1>
    <div class="err"><strong>⚠️ {{.Title}}</strong><br/>{{.Summary}}</div>
    {{range .Details}}<p>{{.}}</p>{{end}}
    {{if .Steps}}
    <div class="section">
      <h2>🔁 How to reconnect</h2>
      <ol>{{range .Steps}}<li>{{.}}</li>{{end}}</ol>
    </div>
    {{end}}
    <div class="note">
      🔐 If this keeps happening on every restart, the server is generating a new signing key each time it boots.
      Set a persistent <code>MCP_AUTH_SECRET</code> (unique per server) so client registrations and tokens survive restarts.
      Rotating that secret intentionally will always force every connected client through this reconnect flow once.
    </div>
  </div>
</body>
</html>`))

func (s *Server) renderAuthError(w http.ResponseWriter, r *http.Request, status int, view authErrorView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoStoreHeaders(w)
	w.WriteHeader(status)
	if err := authErrorTemplate.Execute(w, view); err != nil {
		klog.FromContext(r.Context()).Error(err, "failed to render auth error page")
	}
}

func (s *Server) handleKubeLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderKubeLogin(w, r, kubeLoginView{RequestToken: r.URL.Query().Get("request")})
	case http.MethodPost:
		s.handleKubeLoginPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type kubePreviewError struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

func (s *Server) handleKubePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		withCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	content, err := s.readKubePreviewContent(r)
	if err != nil {
		writeJSON(w, http.StatusOK, kubePreviewError{Error: err.Error()})
		return
	}
	preview, err := PreviewKubeconfig(content)
	if err != nil {
		writeJSON(w, http.StatusOK, kubePreviewError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) readKubePreviewContent(r *http.Request) ([]byte, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			Mode       string `json:"mode"`
			Kubeconfig string `json:"kubeconfig"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, fmt.Errorf("invalid JSON body: %w", err)
		}
		if req.Mode == "existing" {
			b, err := os.ReadFile(s.kubeconfigPath())
			if err != nil {
				return nil, fmt.Errorf("failed to read existing kubeconfig: %w", err)
			}
			return b, nil
		}
		if strings.TrimSpace(req.Kubeconfig) == "" {
			return nil, fmt.Errorf("kubeconfig content is empty")
		}
		return []byte(req.Kubeconfig), nil
	}

	if err := r.ParseMultipartForm(16 << 20); err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}
	if r.FormValue("mode") == "existing" {
		b, err := os.ReadFile(s.kubeconfigPath())
		if err != nil {
			return nil, fmt.Errorf("failed to read existing kubeconfig: %w", err)
		}
		return b, nil
	}
	if text := r.FormValue("kubeconfig"); strings.TrimSpace(text) != "" {
		return []byte(text), nil
	}
	if text := r.FormValue("kubeconfig_paste"); strings.TrimSpace(text) != "" {
		return []byte(text), nil
	}

	f, _, err := r.FormFile("kubeconfig_upload")
	if err != nil {
		return nil, fmt.Errorf("kubeconfig content is empty")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read uploaded file: %w", err)
	}
	return b, nil
}

func (s *Server) renderKubeLogin(w http.ResponseWriter, r *http.Request, view kubeLoginView) {
	path := s.kubeconfigPath()
	view.ExistingPath = path
	if _, err := os.Stat(path); err == nil {
		view.HasExisting = true
	}
	if view.DefaultMode == "" {
		view.DefaultMode = "paste"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoStoreHeaders(w)
	if err := kubeLoginTemplate.Execute(w, view); err != nil {
		klog.FromContext(r.Context()).Error(err, "failed to render kube login")
	}
}

func (s *Server) handleKubeLoginPost(w http.ResponseWriter, r *http.Request) {
	logger := klog.FromContext(r.Context())
	path := s.kubeconfigPath()

	if err := r.ParseMultipartForm(16 << 20); err != nil {
		s.renderKubeLogin(w, r, kubeLoginView{Error: "Failed to parse form"})
		return
	}
	mode := r.FormValue("mode")
	oauthReq := r.FormValue("request")

	var content []byte
	switch mode {
	case "existing":
		b, err := os.ReadFile(path)
		if err != nil {
			s.renderKubeLogin(w, r, kubeLoginView{Error: fmt.Sprintf("Failed to read existing kubeconfig: %v", err), RequestToken: oauthReq, DefaultMode: "existing"})
			return
		}
		content = b
	case "paste":
		text := r.FormValue("kubeconfig_paste")
		content = []byte(text)
		if strings.TrimSpace(text) == "" {
			s.renderKubeLogin(w, r, kubeLoginView{Error: "Pasted kubeconfig is empty", RequestToken: oauthReq, DefaultMode: "paste"})
			return
		}
	case "upload":
		f, _, err := r.FormFile("kubeconfig_upload")
		if err != nil {
			s.renderKubeLogin(w, r, kubeLoginView{Error: "No file uploaded", RequestToken: oauthReq, DefaultMode: "upload"})
			return
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(f)
		if err != nil {
			s.renderKubeLogin(w, r, kubeLoginView{Error: "Failed to read uploaded file", RequestToken: oauthReq, DefaultMode: "upload"})
			return
		}
		content = b
	default:
		s.renderKubeLogin(w, r, kubeLoginView{Error: "Invalid mode", RequestToken: oauthReq})
		return
	}

	validationPath := path
	candidatePath := ""
	if mode == "paste" || mode == "upload" {
		var cleanupCandidate func() error
		var err error
		candidatePath, cleanupCandidate, err = writeKubeconfigCandidate(path, content)
		if err != nil {
			s.renderKubeLogin(w, r, kubeLoginView{Error: err.Error(), RequestToken: oauthReq, DefaultMode: mode})
			return
		}
		defer func() {
			if candidatePath == "" {
				return
			}
			if err := cleanupCandidate(); err != nil && !errors.Is(err, os.ErrNotExist) {
				logger.Error(err, "failed to remove temporary kubeconfig candidate")
			}
		}()
		validationPath = candidatePath
	}

	s.configureMu.Lock()
	defer s.configureMu.Unlock()

	facts, err := s.validate(r.Context(), validationPath)
	if err != nil {
		s.renderKubeLogin(w, r, kubeLoginView{Error: fmt.Sprintf("Kubeconfig validation failed: %v", err), RequestToken: oauthReq, DefaultMode: mode})
		return
	}

	if candidatePath != "" {
		if err := os.Rename(candidatePath, path); err != nil {
			s.renderKubeLogin(w, r, kubeLoginView{Error: fmt.Sprintf("Failed to write kubeconfig: %v", err), RequestToken: oauthReq, DefaultMode: mode})
			return
		}
		candidatePath = ""
	}

	prov, err := s.buildProv(r.Context())
	if err != nil {
		s.renderKubeLogin(w, r, kubeLoginView{Error: fmt.Sprintf("Failed to build Kubernetes provider: %v", err), RequestToken: oauthReq, DefaultMode: mode})
		return
	}
	s.dyn.SetProvider(prov)
	if err := s.mcpServer.ReloadConfiguration(r.Context(), s.cfgState.Load()); err != nil {
		logger.Error(err, "failed to reload MCP configuration after kubeconfig bootstrap")
		s.renderKubeLogin(w, r, kubeLoginView{Error: fmt.Sprintf("Failed to reload MCP server configuration: %v", err), RequestToken: oauthReq, DefaultMode: mode})
		return
	}
	facts.Tools = sortedCopy(s.mcpServer.GetEnabledTools())
	facts.normalize()

	if oauthReq != "" {
		// Kubernetes access is already enabled at this point (provider set + config
		// reloaded above). Only the OAuth code hand-off can still fail if the sealed
		// auth request can no longer be verified — key rotation, or the 10-minute
		// auth-request TTL lapsing while the user filled in the login form.
		areq := authRequest{}
		if err := s.sealer.Unseal(tokenTypeAuthRequest, oauthReq, &areq); err != nil {
			s.renderAuthError(w, r, http.StatusBadRequest, authErrorView{
				Title:   "Reconnect required",
				Summary: "Kubernetes access was enabled, but this sign-in request could not be verified.",
				Details: []template.HTML{
					`This server's signing key (<code>MCP_AUTH_SECRET</code>) changed while you were signing in, so the authorization request can no longer be verified.`,
					`Your kubeconfig was accepted — you only need to restart the sign-in from your MCP client so it can complete the handshake.`,
				},
				Steps: reconnectSteps,
			})
			return
		}
		if err := areq.validate(s.now()); err != nil {
			s.renderAuthError(w, r, http.StatusBadRequest, authErrorView{
				Title:   "Sign-in request expired",
				Summary: "Kubernetes access was enabled, but this sign-in request timed out before it completed.",
				Details: []template.HTML{
					`Authorization requests are valid for a short window. This one expired before the login finished.`,
					`Your kubeconfig was accepted — simply start the connection again from your MCP client to finish authorizing.`,
				},
				Steps: reconnectSteps,
			})
			return
		}
		code, err := s.issueAuthCode(authCode{
			tokenBase:           newTokenBase(s.now(), 2*time.Minute),
			ClientID:            areq.ClientID,
			RedirectURI:         areq.RedirectURI,
			Scope:               areq.Scope,
			CodeChallenge:       areq.CodeChallenge,
			CodeChallengeMethod: areq.CodeChallengeMethod,
		})
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		facts.RedirectURL = template.URL(redirectWithCode(areq.RedirectURI, code, areq.State))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setNoStoreHeaders(w)
		if err := kubeSuccessTemplate.Execute(w, facts); err != nil {
			logger.Error(err, "failed to render success page")
		}
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoStoreHeaders(w)
	if err := kubeSuccessTemplate.Execute(w, facts); err != nil {
		logger.Error(err, "failed to render success page")
	}
}
func writeKubeconfigCandidate(path string, content []byte) (string, func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", nil, fmt.Errorf("failed to create kubeconfig directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary kubeconfig: %w", err)
	}
	candidatePath := tmp.Name()
	cleanup := func() error {
		return os.Remove(candidatePath)
	}
	if _, err := tmp.Write(content); err != nil {
		closeErr := tmp.Close()
		removeErr := cleanup()
		if closeErr != nil {
			return "", nil, fmt.Errorf("failed to write temporary kubeconfig: %w; close failed: %v", err, closeErr)
		}
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return "", nil, fmt.Errorf("failed to write temporary kubeconfig: %w; cleanup failed: %v", err, removeErr)
		}
		return "", nil, fmt.Errorf("failed to write temporary kubeconfig: %w", err)
	}
	if err := tmp.Close(); err != nil {
		removeErr := cleanup()
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return "", nil, fmt.Errorf("failed to close temporary kubeconfig: %w; cleanup failed: %v", err, removeErr)
		}
		return "", nil, fmt.Errorf("failed to close temporary kubeconfig: %w", err)
	}
	if err := os.Chmod(candidatePath, 0o600); err != nil {
		removeErr := cleanup()
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return "", nil, fmt.Errorf("failed to secure temporary kubeconfig: %w; cleanup failed: %v", err, removeErr)
		}
		return "", nil, fmt.Errorf("failed to secure temporary kubeconfig: %w", err)
	}
	return candidatePath, cleanup, nil
}

func sortedCopy(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

func contains(items []string, v string) bool {
	for _, s := range items {
		if s == v {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	withCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	setNoStoreHeaders(w)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func setNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func withCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
