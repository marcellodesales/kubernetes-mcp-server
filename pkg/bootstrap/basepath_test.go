package bootstrap

import (
	"bytes"
	"strings"
	"testing"
)

// TestKubeLoginTemplateBasePath ensures the bootstrap login page is base-path aware:
// the form action carries the public prefix, and the /kube/preview fetch is built
// from a data-base-path attribute (avoiding JS-string escaping of the path). Behind
// a reverse-proxy prefix (e.g. /mcps/kubernetes-mcp) these must not resolve against
// the host root — the bug that broke terminal MCP clients.
func TestKubeLoginTemplateBasePath(t *testing.T) {
	render := func(basePath string) string {
		var buf bytes.Buffer
		if err := kubeLoginTemplate.Execute(&buf, kubeLoginView{DefaultMode: "paste", BasePath: basePath}); err != nil {
			t.Fatalf("execute template: %v", err)
		}
		return buf.String()
	}

	// The fetch always reads basePath from the data attribute at runtime, so the
	// source form is identical regardless of prefix.
	const fetchCall = `fetch(basePath + '/kube/preview'`

	t.Run("behind path prefix", func(t *testing.T) {
		out := render("/mcps/kubernetes-mcp")
		for _, want := range []string{
			`action="/mcps/kubernetes-mcp/kube/login"`,
			`data-base-path="/mcps/kubernetes-mcp"`,
			fetchCall,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("login page missing %q", want)
			}
		}
		if strings.Contains(out, `action="/kube/login"`) {
			t.Error("login page still emits a root-relative form action (would 404 behind a prefix)")
		}
	})

	t.Run("at host root", func(t *testing.T) {
		out := render("")
		for _, want := range []string{
			`action="/kube/login"`,
			`data-base-path=""`,
			fetchCall,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("root login page missing %q", want)
			}
		}
	})
}
