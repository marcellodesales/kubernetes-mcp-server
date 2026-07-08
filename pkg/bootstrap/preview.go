package bootstrap

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"
)

type KubeconfigPreview struct {
	Valid                  bool                       `json:"valid"`
	Format                 string                     `json:"format"`
	APIVersion             string                     `json:"apiVersion"`
	Kind                   string                     `json:"kind"`
	CurrentContext         string                     `json:"currentContext"`
	DeclaredCurrentContext string                     `json:"declaredCurrentContext,omitempty"`
	Clusters               []KubeconfigClusterPreview `json:"clusters"`
	Users                  []KubeconfigUserPreview    `json:"users"`
	Contexts               []KubeconfigContextPreview `json:"contexts"`
}

type KubeconfigClusterPreview struct {
	Name                  string                       `json:"name"`
	Server                string                       `json:"server"`
	Host                  string                       `json:"host,omitempty"`
	TLSServerName         string                       `json:"tlsServerName,omitempty"`
	InsecureSkipTLSVerify bool                         `json:"insecureSkipTLSVerify,omitempty"`
	Current               bool                         `json:"current"`
	ContextNames          []string                     `json:"contextNames,omitempty"`
	Certificate           KubeconfigCertificatePreview `json:"certificate"`
}

type KubeconfigCertificatePreview struct {
	Present       bool     `json:"present"`
	Source        string   `json:"source,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	ExpiresAt     string   `json:"expiresAt,omitempty"`
	ExpiresInDays int      `json:"expiresInDays,omitempty"`
	Expired       bool     `json:"expired,omitempty"`
	Subjects      []string `json:"subjects,omitempty"`
	Issuers       []string `json:"issuers,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type KubeconfigUserPreview struct {
	Name                 string `json:"name"`
	AuthMethod           string `json:"authMethod"`
	TokenPreview         string `json:"tokenPreview,omitempty"`
	TokenFile            string `json:"tokenFile,omitempty"`
	ExecCommand          string `json:"execCommand,omitempty"`
	Username             string `json:"username,omitempty"`
	HasClientCertificate bool   `json:"hasClientCertificate,omitempty"`
	HasClientKey         bool   `json:"hasClientKey,omitempty"`
}

type KubeconfigContextPreview struct {
	Name      string `json:"name"`
	Cluster   string `json:"cluster"`
	User      string `json:"user"`
	Namespace string `json:"namespace,omitempty"`
	Current   bool   `json:"current"`
}

type kubeconfigTypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

func PreviewKubeconfig(raw []byte) (*KubeconfigPreview, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("kubeconfig content is empty")
	}

	format := "yaml"
	if json.Valid(raw) {
		format = "json"
	}

	var meta kubeconfigTypeMeta
	if err := yaml.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse YAML/JSON metadata: %w", err)
	}
	if meta.APIVersion != "" && meta.APIVersion != "v1" {
		return nil, fmt.Errorf("unsupported kubeconfig apiVersion %q (expected v1)", meta.APIVersion)
	}
	if meta.Kind != "" && meta.Kind != "Config" {
		return nil, fmt.Errorf("unsupported kubeconfig kind %q (expected Config)", meta.Kind)
	}

	cfg, err := clientcmd.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig YAML/JSON: %w", err)
	}
	currentContext, err := resolveContextName(cfg)
	if err != nil {
		return nil, err
	}
	currentCtx := cfg.Contexts[currentContext]
	if currentCtx == nil {
		return nil, fmt.Errorf("kubeconfig context %q not found", currentContext)
	}
	if currentCtx.Cluster == "" {
		return nil, fmt.Errorf("kubeconfig context %q does not reference a cluster", currentContext)
	}
	if cfg.Clusters[currentCtx.Cluster] == nil {
		return nil, fmt.Errorf("kubeconfig cluster %q not found", currentCtx.Cluster)
	}

	contextNamesByCluster := map[string][]string{}
	for name, ctx := range cfg.Contexts {
		if ctx == nil || ctx.Cluster == "" {
			continue
		}
		contextNamesByCluster[ctx.Cluster] = append(contextNamesByCluster[ctx.Cluster], name)
	}
	for clusterName := range contextNamesByCluster {
		sort.Strings(contextNamesByCluster[clusterName])
	}

	preview := &KubeconfigPreview{
		Valid:                  true,
		Format:                 format,
		APIVersion:             valueOr(meta.APIVersion, "v1"),
		Kind:                   valueOr(meta.Kind, "Config"),
		CurrentContext:         currentContext,
		DeclaredCurrentContext: cfg.CurrentContext,
		Clusters:               previewClusters(cfg, currentCtx.Cluster, contextNamesByCluster),
		Users:                  previewUsers(cfg),
		Contexts:               previewContexts(cfg, currentContext),
	}
	return preview, nil
}

func previewClusters(cfg *clientcmdapi.Config, currentCluster string, contextNamesByCluster map[string][]string) []KubeconfigClusterPreview {
	names := sortedClusterNames(cfg)
	out := make([]KubeconfigClusterPreview, 0, len(names))
	for _, name := range names {
		cluster := cfg.Clusters[name]
		if cluster == nil {
			continue
		}
		out = append(out, KubeconfigClusterPreview{
			Name:                  name,
			Server:                cluster.Server,
			Host:                  hostFromServer(cluster.Server),
			TLSServerName:         cluster.TLSServerName,
			InsecureSkipTLSVerify: cluster.InsecureSkipTLSVerify,
			Current:               name == currentCluster,
			ContextNames:          append([]string(nil), contextNamesByCluster[name]...),
			Certificate:           previewCertificate(cluster, time.Now().UTC()),
		})
	}
	return out
}

func previewUsers(cfg *clientcmdapi.Config) []KubeconfigUserPreview {
	names := sortedAuthInfoNames(cfg)
	out := make([]KubeconfigUserPreview, 0, len(names))
	for _, name := range names {
		auth := cfg.AuthInfos[name]
		if auth == nil {
			continue
		}
		user := KubeconfigUserPreview{
			Name:                 name,
			AuthMethod:           classifyAuthMethod(cfg, name),
			TokenPreview:         redactSecret(auth.Token),
			TokenFile:            auth.TokenFile,
			Username:             auth.Username,
			HasClientCertificate: len(auth.ClientCertificateData) > 0 || auth.ClientCertificate != "",
			HasClientKey:         len(auth.ClientKeyData) > 0 || auth.ClientKey != "",
		}
		if auth.Exec != nil {
			user.ExecCommand = auth.Exec.Command
		}
		out = append(out, user)
	}
	return out
}

func previewContexts(cfg *clientcmdapi.Config, currentContext string) []KubeconfigContextPreview {
	names := sortedContextNames(cfg)
	out := make([]KubeconfigContextPreview, 0, len(names))
	for _, name := range names {
		ctx := cfg.Contexts[name]
		if ctx == nil {
			continue
		}
		out = append(out, KubeconfigContextPreview{
			Name:      name,
			Cluster:   ctx.Cluster,
			User:      ctx.AuthInfo,
			Namespace: ctx.Namespace,
			Current:   name == currentContext,
		})
	}
	return out
}

func previewCertificate(cluster *clientcmdapi.Cluster, now time.Time) KubeconfigCertificatePreview {
	if cluster == nil {
		return KubeconfigCertificatePreview{}
	}
	if cluster.InsecureSkipTLSVerify {
		return KubeconfigCertificatePreview{
			Present: true,
			Source:  "insecure-skip-tls-verify",
			Summary: "TLS verification is disabled for this cluster",
		}
	}
	if len(cluster.CertificateAuthorityData) == 0 {
		if cluster.CertificateAuthority != "" {
			return KubeconfigCertificatePreview{
				Present: true,
				Source:  "certificate-authority",
				Summary: "CA certificate file reference (not inspected during preview): " + cluster.CertificateAuthority,
			}
		}
		return KubeconfigCertificatePreview{
			Present: false,
			Summary: "No certificate authority data or file reference",
		}
	}

	certs, err := parseCertificates(cluster.CertificateAuthorityData)
	if err != nil {
		return KubeconfigCertificatePreview{
			Present: true,
			Source:  "certificate-authority-data",
			Summary: "CA data is present but could not be parsed as an X.509 certificate",
			Error:   err.Error(),
		}
	}
	soonest := certs[0]
	for _, cert := range certs[1:] {
		if cert.NotAfter.Before(soonest.NotAfter) {
			soonest = cert
		}
	}

	subjects := make([]string, 0, len(certs))
	issuers := make([]string, 0, len(certs))
	for _, cert := range certs {
		subjects = append(subjects, cert.Subject.String())
		issuers = append(issuers, cert.Issuer.String())
	}

	days := int(soonest.NotAfter.Sub(now).Hours() / 24)
	return KubeconfigCertificatePreview{
		Present:       true,
		Source:        "certificate-authority-data",
		Summary:       fmt.Sprintf("%d certificate(s), earliest expiry %s", len(certs), soonest.NotAfter.Format("2006-01-02")),
		ExpiresAt:     soonest.NotAfter.Format(time.RFC3339),
		ExpiresInDays: days,
		Expired:       now.After(soonest.NotAfter),
		Subjects:      subjects,
		Issuers:       issuers,
	}
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func sortedClusterNames(cfg *clientcmdapi.Config) []string {
	names := make([]string, 0, len(cfg.Clusters))
	for name := range cfg.Clusters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedAuthInfoNames(cfg *clientcmdapi.Config) []string {
	names := make([]string, 0, len(cfg.AuthInfos))
	for name := range cfg.AuthInfos {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedContextNames(cfg *clientcmdapi.Config) []string {
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func hostFromServer(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}
	return u.Host
}

func redactSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	runes := []rune(secret)
	if len(runes) <= 8 {
		return strings.Repeat("•", len(runes))
	}
	if len(runes) <= 18 {
		return string(runes[:3]) + "…" + string(runes[len(runes)-3:])
	}
	return string(runes[:8]) + "…" + string(runes[len(runes)-6:])
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
