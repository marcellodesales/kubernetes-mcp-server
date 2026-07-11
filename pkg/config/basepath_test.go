package config

import "testing"

func TestStaticConfigBasePath(t *testing.T) {
	cases := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"prefixed", "https://dev.vionix.kortex.vionix.viasat.io/mcps/kubernetes-mcp", "/mcps/kubernetes-mcp"},
		{"prefixed trailing slash", "https://host/mcps/kubernetes-mcp/", "/mcps/kubernetes-mcp"},
		{"deep path", "https://host/a/b/c", "/a/b/c"},
		{"root host only", "https://host", ""},
		{"root slash", "https://host/", ""},
		{"empty (localhost/no prefix)", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (&StaticConfig{ServerURL: tc.serverURL}).BasePath()
			if got != tc.want {
				t.Errorf("BasePath(%q) = %q, want %q", tc.serverURL, got, tc.want)
			}
		})
	}
}
