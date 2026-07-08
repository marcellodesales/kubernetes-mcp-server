package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPreviewKubeconfigSummarizesSanitizedConfig(t *testing.T) {
	certDER := testCertificateDER(t)
	caData := base64.StdEncoding.EncodeToString(certDER)
	raw := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: az-eastus-seceng-devsecops-prod
  cluster:
    server: https://console.rancher.az.viasat.com/k8s/clusters/c-m-ssrsjmh2
    certificate-authority-data: %q
- name: az-eastus-seceng-devsecops-prod-fqdn
  cluster:
    server: https://az-eastus-seceng-devsecops-prod-api.rancher.az.viasat.com
    certificate-authority-data: %q
users:
- name: az-eastus-seceng-devsecops-prod
  user:
    token: kubecoabcdefghijklmnopqrstuvwxyz85pgdqbc526rx
contexts:
- name: az-eastus-seceng-devsecops-prod
  context:
    user: az-eastus-seceng-devsecops-prod
    cluster: az-eastus-seceng-devsecops-prod
- name: az-eastus-seceng-devsecops-prod-fqdn
  context:
    user: az-eastus-seceng-devsecops-prod
    cluster: az-eastus-seceng-devsecops-prod-fqdn
current-context: az-eastus-seceng-devsecops-prod
`, caData, caData)

	preview, err := PreviewKubeconfig([]byte(raw))
	if err != nil {
		t.Fatalf("PreviewKubeconfig: %v", err)
	}
	if !preview.Valid {
		t.Fatalf("expected preview to be valid")
	}
	if preview.APIVersion != "v1" || preview.Kind != "Config" {
		t.Fatalf("unexpected type metadata: %s %s", preview.APIVersion, preview.Kind)
	}
	if preview.CurrentContext != "az-eastus-seceng-devsecops-prod" {
		t.Fatalf("unexpected current context %q", preview.CurrentContext)
	}
	if len(preview.Clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(preview.Clusters))
	}
	if !preview.Clusters[0].Current {
		t.Fatalf("expected first sorted cluster to be current")
	}
	if preview.Clusters[0].Server != "https://console.rancher.az.viasat.com/k8s/clusters/c-m-ssrsjmh2" {
		t.Fatalf("unexpected server %q", preview.Clusters[0].Server)
	}
	if preview.Clusters[0].Host != "console.rancher.az.viasat.com" {
		t.Fatalf("unexpected host %q", preview.Clusters[0].Host)
	}
	if !preview.Clusters[0].Certificate.Present || preview.Clusters[0].Certificate.ExpiresInDays <= 300 {
		t.Fatalf("expected certificate expiration summary, got %#v", preview.Clusters[0].Certificate)
	}
	if len(preview.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(preview.Users))
	}
	if preview.Users[0].AuthMethod != "token" {
		t.Fatalf("expected token auth, got %q", preview.Users[0].AuthMethod)
	}
	if preview.Users[0].TokenPreview == "" || strings.Contains(preview.Users[0].TokenPreview, "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("expected redacted token preview, got %q", preview.Users[0].TokenPreview)
	}
	if len(preview.Contexts) != 2 || !preview.Contexts[0].Current {
		t.Fatalf("expected sorted contexts with current flag, got %#v", preview.Contexts)
	}
}

func TestPreviewKubeconfigRejectsMalformedConfig(t *testing.T) {
	_, err := PreviewKubeconfig([]byte("apiVersion: v1\nkind: Config\nclusters:\n- nope"))
	if err == nil {
		t.Fatalf("expected malformed kubeconfig to fail")
	}
}

func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Viasat Test Root CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}
