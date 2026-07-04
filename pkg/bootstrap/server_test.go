package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/config"
	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/mcp"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeProvider struct{}

func (p *fakeProvider) IsOpenShift(context.Context) bool { return false }
func (p *fakeProvider) IsMultiTarget() bool              { return false }
func (p *fakeProvider) GetTargets(context.Context) ([]string, error) {
	return []string{""}, nil
}

func TestKubeLoginPostRendersClusterDashboard(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	t.Setenv("MCP_AUTH_SECRET", key)

	cfg := config.BaseDefault()
	cfg.BootstrapUI = true
	cfg.Port = "8080"
	cfg.ClusterAuthMode = api.ClusterAuthKubeconfig
	cfg.ClusterProviderStrategy = api.ClusterProviderKubeConfig
	cfg.KubeConfig = t.TempDir() + "/kube/config"
	cfgState := config.NewStaticConfigState(cfg)

	dyn := kubernetes.NewDynamicProvider()
	mcpServer, err := mcp.NewServer(context.Background(), mcp.Configuration{StaticConfig: cfg}, dyn)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}

	b, err := NewServer(Options{
		CfgState:        cfgState,
		McpServer:       mcpServer,
		DynamicProvider: dyn,
		ProviderBuilder: func(ctx context.Context) (kubernetes.Provider, error) { return &fakeProvider{}, nil },
		KubeconfigValidator: func(ctx context.Context, kubeconfigPath string) (*ClusterFacts, error) {
			return &ClusterFacts{
				APIServerURL:   "https://example.invalid:6443",
				ContextName:    "ctx",
				UserName:       "user",
				AuthMethod:     "token",
				ClusterVersion: "v1.30.0",
				Namespaces:     []string{"default", "kube-system"},
				Nodes:          []string{"node-1"},
				ServiceAccounts: []string{
					"default/default",
					"kube-system/coredns",
				},
				CRDs: []string{"widgets.example.com"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("mode", "paste")
	_ = mw.WriteField("kubeconfig_paste", "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n")
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/kube/login", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /kube/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		"✅ 3. Current state",
		"URL</span><code>https://example.invalid:6443</code>",
		"Host</span><code>example.invalid:6443</code>",
		"Namespaces (2)",
		"Nodes (1)",
		"Service Accounts (2)",
		"CRDs (1)",
		"Tools (",
		"default/default",
		"widgets.example.com",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected dashboard HTML to contain %q", want)
		}
	}
}

func TestKubeLoginPostDoesNotPersistInvalidPastedKubeconfig(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	t.Setenv("MCP_AUTH_SECRET", key)

	kubeconfigPath := t.TempDir() + "/kube/config"
	original := []byte("apiVersion: v1\nkind: Config\ncurrent-context: original\n")
	if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0o700); err != nil {
		t.Fatalf("mkdir kubeconfig dir: %v", err)
	}
	if err := os.WriteFile(kubeconfigPath, original, 0o600); err != nil {
		t.Fatalf("write original kubeconfig: %v", err)
	}

	cfg := config.BaseDefault()
	cfg.BootstrapUI = true
	cfg.Port = "8080"
	cfg.ClusterAuthMode = api.ClusterAuthKubeconfig
	cfg.ClusterProviderStrategy = api.ClusterProviderKubeConfig
	cfg.KubeConfig = kubeconfigPath
	cfgState := config.NewStaticConfigState(cfg)

	dyn := kubernetes.NewDynamicProvider()
	mcpServer, err := mcp.NewServer(context.Background(), mcp.Configuration{StaticConfig: cfg}, dyn)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}

	b, err := NewServer(Options{
		CfgState:        cfgState,
		McpServer:       mcpServer,
		DynamicProvider: dyn,
		ProviderBuilder: func(ctx context.Context) (kubernetes.Provider, error) { return &fakeProvider{}, nil },
		KubeconfigValidator: func(ctx context.Context, kubeconfigPath string) (*ClusterFacts, error) {
			content, err := os.ReadFile(kubeconfigPath)
			if err != nil {
				return nil, err
			}
			if strings.Contains(string(content), "invalid-candidate") {
				return nil, errors.New("invalid candidate")
			}
			return &ClusterFacts{APIServerURL: "https://example.invalid", ContextName: "ctx"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("mode", "paste")
	_ = mw.WriteField("kubeconfig_paste", "invalid-candidate")
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/kube/login", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /kube/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "Kubeconfig validation failed") {
		t.Fatalf("expected validation error page")
	}
	got, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		t.Fatalf("read final kubeconfig: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("invalid candidate replaced existing kubeconfig")
	}
}

func (p *fakeProvider) GetDerivedKubernetes(context.Context, string) (*kubernetes.Kubernetes, error) {
	return nil, kubernetes.ErrProviderNotConfigured
}
func (p *fakeProvider) GetDefaultTarget() string                           { return "" }
func (p *fakeProvider) GetTargetParameterName() string                     { return "" }
func (p *fakeProvider) WatchTargets(context.Context, kubernetes.McpReload) {}
func (p *fakeProvider) Close()                                             {}
func (p *fakeProvider) HasGVKs(context.Context, []schema.GroupVersionKind) bool {
	return true
}
func TestKubeLoginGetStartsFreshWithThreeSteps(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x66}, 32))
	t.Setenv("MCP_AUTH_SECRET", key)

	cfg := config.BaseDefault()
	cfg.BootstrapUI = true
	cfg.Port = "8080"
	cfg.ClusterAuthMode = api.ClusterAuthKubeconfig
	cfg.ClusterProviderStrategy = api.ClusterProviderKubeConfig
	cfg.KubeConfig = t.TempDir() + "/kube/config"
	if err := os.MkdirAll(filepath.Dir(cfg.KubeConfig), 0o700); err != nil {
		t.Fatalf("mkdir kubeconfig dir: %v", err)
	}
	if err := os.WriteFile(cfg.KubeConfig, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatalf("write existing kubeconfig: %v", err)
	}
	cfgState := config.NewStaticConfigState(cfg)

	dyn := kubernetes.NewDynamicProvider()
	mcpServer, err := mcp.NewServer(context.Background(), mcp.Configuration{StaticConfig: cfg}, dyn)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}

	b, err := NewServer(Options{
		CfgState:        cfgState,
		McpServer:       mcpServer,
		DynamicProvider: dyn,
		ProviderBuilder: func(ctx context.Context) (kubernetes.Provider, error) { return &fakeProvider{}, nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/kube/login")
	if err != nil {
		t.Fatalf("GET /kube/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") || !strings.Contains(got, "no-cache") {
		t.Fatalf("expected no-store/no-cache header, got %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		`<button id="stepSource" type="button" class="step active">`,
		`<button id="stepReview" type="button" class="step">`,
		`<button id="stepCurrent" type="button" class="step">`,
		"🔎 1. Source validation",
		"⏳ 2. Review target",
		"⏳ 3. Current state",
		`autocomplete="off"`,
		"stepReview.addEventListener('click'",
		"stepCurrent.addEventListener('click'",
		"cache: 'no-store'",
		"button.loading",
		`<span class="spinner" aria-hidden="true"></span> Enabling Kubernetes Access…`,
		"form.classList.add('submitting')",
		"Validating live cluster access and loading the current-state dashboard",
		"initializeFreshSourceState();",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected login HTML to contain %q", want)
		}
	}
	if strings.Contains(html, `id="mode_existing" type="radio" name="mode" value="existing" autocomplete="off" checked`) {
		t.Fatalf("expected existing kubeconfig mode not to be selected by default")
	}
}

func TestSealerRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	sealer, err := NewSealer(key, "test")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	in := map[string]any{"a": "b", "n": 1}
	tok, err := sealer.Seal("t", in)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	out := map[string]any{}
	if err := sealer.Unseal("t", tok, &out); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if out["a"] != "b" {
		t.Fatalf("unexpected out[a]=%v", out["a"])
	}
}

func TestPKCES256(t *testing.T) {
	verifier := strings.Repeat("a", 50)
	challenge, err := S256Challenge(verifier)
	if err != nil {
		t.Fatalf("S256Challenge: %v", err)
	}
	if err := VerifyPKCES256(challenge, verifier); err != nil {
		t.Fatalf("VerifyPKCES256: %v", err)
	}
}

func TestValidateRedirectURIAllowsMCPClientSchemes(t *testing.T) {
	tests := []string{
		"http://localhost:8080/callback",
		"https://example.com/callback",
		"warp://mcp/oauth/callback",
		"warppreview://mcp/oauth/callback",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if err := validateRedirectURI(tt); err != nil {
				t.Fatalf("validateRedirectURI(%q): %v", tt, err)
			}
		})
	}
}

func TestValidateRedirectURIRejectsMalformedValues(t *testing.T) {
	tests := []string{
		"",
		"/relative/callback",
		"warp:/missing-host",
		"http://example.com/callback#fragment",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if err := validateRedirectURI(tt); err == nil {
				t.Fatalf("expected validateRedirectURI(%q) to fail", tt)
			}
		})
	}
}

func TestRegisterAcceptsWarpRedirectURI(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	t.Setenv("MCP_AUTH_SECRET", key)

	cfg := config.BaseDefault()
	cfg.BootstrapUI = true
	cfg.Port = "8080"
	cfg.ClusterAuthMode = api.ClusterAuthKubeconfig
	cfg.ClusterProviderStrategy = api.ClusterProviderKubeConfig
	cfg.KubeConfig = t.TempDir() + "/kube/config"
	cfgState := config.NewStaticConfigState(cfg)

	dyn := kubernetes.NewDynamicProvider()
	mcpServer, err := mcp.NewServer(context.Background(), mcp.Configuration{StaticConfig: cfg}, dyn)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}

	b, err := NewServer(Options{
		CfgState:        cfgState,
		McpServer:       mcpServer,
		DynamicProvider: dyn,
		ProviderBuilder: func(ctx context.Context) (kubernetes.Provider, error) { return &fakeProvider{}, nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	callback := "warp://mcp/oauth/callback"
	regBody, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{callback},
		"client_name":   "Warp",
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var regResp registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if regResp.ClientID == "" {
		t.Fatalf("expected client_id")
	}
	if len(regResp.RedirectURIs) != 1 || regResp.RedirectURIs[0] != callback {
		t.Fatalf("expected redirect URI %q, got %#v", callback, regResp.RedirectURIs)
	}
}
func TestAuthorizeRedirectsToLoginWhenProviderAlreadyConfigured(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	t.Setenv("MCP_AUTH_SECRET", key)

	cfg := config.BaseDefault()
	cfg.BootstrapUI = true
	cfg.Port = "8080"
	cfg.ClusterAuthMode = api.ClusterAuthKubeconfig
	cfg.ClusterProviderStrategy = api.ClusterProviderKubeConfig
	cfg.KubeConfig = t.TempDir() + "/kube/config"
	cfgState := config.NewStaticConfigState(cfg)

	dyn := kubernetes.NewDynamicProvider()
	dyn.SetProvider(&fakeProvider{})
	mcpServer, err := mcp.NewServer(context.Background(), mcp.Configuration{StaticConfig: cfg}, dyn)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}

	b, err := NewServer(Options{
		CfgState:        cfgState,
		McpServer:       mcpServer,
		DynamicProvider: dyn,
		ProviderBuilder: func(ctx context.Context) (kubernetes.Provider, error) { return &fakeProvider{}, nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	callback := "warp://mcp/oauth2callback"
	regBody, _ := json.Marshal(map[string]any{"redirect_uris": []string{callback}})
	resp, err := http.Post(ts.URL+"/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var regResp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	verifier := strings.Repeat("b", 50)
	challenge, err := S256Challenge(verifier)
	if err != nil {
		t.Fatalf("S256Challenge: %v", err)
	}
	authURL := ts.URL + "/authorize?response_type=code" +
		"&client_id=" + url.QueryEscape(regResp.ClientID) +
		"&redirect_uri=" + url.QueryEscape(callback) +
		"&state=logout-login" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = client.Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/kube/login?request=") {
		t.Fatalf("expected configured provider to still redirect to kube login, got %q", loc)
	}
	if strings.HasPrefix(loc, callback) || strings.Contains(loc, "code=") {
		t.Fatalf("expected no auto-granted callback code, got %q", loc)
	}
}

func TestBootstrapOAuthHappyPath(t *testing.T) {
	// Ensure a stable test key so NewServer doesn't depend on ambient env.
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	t.Setenv("MCP_AUTH_SECRET", key)

	cfg := config.BaseDefault()
	cfg.BootstrapUI = true
	cfg.Port = "8080"
	cfg.ClusterAuthMode = api.ClusterAuthKubeconfig
	cfg.ClusterProviderStrategy = api.ClusterProviderKubeConfig
	cfg.KubeConfig = t.TempDir() + "/kube/config"
	cfgState := config.NewStaticConfigState(cfg)

	dyn := kubernetes.NewDynamicProvider()
	mcpServer, err := mcp.NewServer(context.Background(), mcp.Configuration{StaticConfig: cfg}, dyn)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}

	b, err := NewServer(Options{
		CfgState:        cfgState,
		McpServer:       mcpServer,
		DynamicProvider: dyn,
		ProviderBuilder: func(ctx context.Context) (kubernetes.Provider, error) { return &fakeProvider{}, nil },
		KubeconfigValidator: func(ctx context.Context, kubeconfigPath string) (*ClusterFacts, error) {
			return &ClusterFacts{
				APIServerURL: "https://example.invalid",
				ContextName:  "ctx",
				UserName:     "user",
				AuthMethod:   "token",
				Namespaces:   []string{"default"},
				Nodes:        []string{"node-1"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)
	mux.Handle("/protected", b.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// 1) protected endpoint without token => 401 + resource_metadata challenge
	resp, err := http.Get(ts.URL + "/protected")
	if err != nil {
		t.Fatalf("GET /protected: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Fatalf("expected WWW-Authenticate resource_metadata challenge, got %q", wwwAuth)
	}

	// 2) dynamic client registration
	callback := "warp://mcp/oauth/callback"
	regBody, _ := json.Marshal(map[string]any{"redirect_uris": []string{callback}})
	resp, err = http.Post(ts.URL+"/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var regResp struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if regResp.ClientID == "" {
		t.Fatalf("expected client_id")
	}

	// 3) authorization request => redirect to /kube/login
	verifier := strings.Repeat("a", 50)
	challenge, _ := S256Challenge(verifier)
	authURL := ts.URL + "/authorize?response_type=code" +
		"&client_id=" + url.QueryEscape(regResp.ClientID) +
		"&redirect_uri=" + url.QueryEscape(callback) +
		"&state=s" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = client.Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/kube/login") {
		t.Fatalf("expected redirect to /kube/login, got %q", loc)
	}
	u, _ := url.Parse(loc)
	oauthReq := u.Query().Get("request")
	if oauthReq == "" {
		t.Fatalf("expected request token in redirect")
	}

	// 4) kube login POST (multipart) => current-state dashboard with callback link
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("mode", "paste")
	_ = mw.WriteField("kubeconfig_paste", "apiVersion: v1\nclusters: []\ncontexts: []\nusers: []\n")
	_ = mw.WriteField("request", oauthReq)
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/kube/login", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST /kube/login: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read dashboard body: %v", err)
	}
	dashboardHTML := string(body)
	if !strings.Contains(dashboardHTML, "✅ 3. Current state") || !strings.Contains(dashboardHTML, "Continue to MCP client") {
		t.Fatalf("expected current-state dashboard with continue link")
	}
	cbLoc := extractHrefByClass(t, dashboardHTML, "continue-action")
	cbURL, _ := url.Parse(cbLoc)
	if cbURL.Scheme == "" {
		// Location might be relative; make it absolute for parsing.
		cbURL, _ = url.Parse("http://example.com" + cbLoc)
	}
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in callback redirect, got %q", cbLoc)
	}

	// 5) exchange code for access token
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", regResp.ClientID)
	form.Set("redirect_uri", callback)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokResp.AccessToken == "" {
		t.Fatalf("expected access_token")
	}

	// 6) protected endpoint with token => 200
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /protected with token: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Ensure reload side effects have time to complete (mostly for race builds).
	time.Sleep(10 * time.Millisecond)
}

func extractHrefByClass(t *testing.T, page, class string) string {
	t.Helper()

	classAttr := `class="` + class + `"`
	classIndex := strings.Index(page, classAttr)
	if classIndex < 0 {
		t.Fatalf("expected HTML to contain class %q", class)
	}
	anchorStart := strings.LastIndex(page[:classIndex], "<a")
	if anchorStart < 0 {
		t.Fatalf("expected class %q to belong to an anchor", class)
	}
	anchorEndRelative := strings.Index(page[anchorStart:], ">")
	if anchorEndRelative < 0 {
		t.Fatalf("expected anchor with class %q to be closed", class)
	}
	anchor := page[anchorStart : anchorStart+anchorEndRelative]
	hrefStart := strings.Index(anchor, `href="`)
	if hrefStart < 0 {
		t.Fatalf("expected anchor with class %q to have href", class)
	}
	hrefStart += len(`href="`)
	hrefEnd := strings.Index(anchor[hrefStart:], `"`)
	if hrefEnd < 0 {
		t.Fatalf("expected href for class %q to be quoted", class)
	}
	return html.UnescapeString(anchor[hrefStart : hrefStart+hrefEnd])
}
