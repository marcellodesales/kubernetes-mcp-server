package bootstrap

import (
	"context"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"sort"
	"time"

	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type ClusterFacts struct {
	APIServerURL   string
	APIHost        string
	ContextName    string
	UserName       string
	AuthMethod     string
	ClusterVersion string
	RedirectURL    template.URL

	Namespaces      []string
	Nodes           []string
	ServiceAccounts []string
	CRDs            []string
	Tools           []string

	NamespaceCount      int
	NodeCount           int
	ServiceAccountCount int
	CRDCount            int

	InventoryWarnings []string
}

func ValidateKubeconfig(ctx context.Context, kubeconfigPath string, maxItems int) (*ClusterFacts, error) {
	b, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kubeconfig: %w", err)
	}
	cfg, err := clientcmd.Load(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	contextName, err := resolveContextName(cfg)
	if err != nil {
		return nil, err
	}
	ctxEntry := cfg.Contexts[contextName]
	if ctxEntry == nil {
		return nil, fmt.Errorf("kubeconfig context %q not found", contextName)
	}

	clusterName := ctxEntry.Cluster
	userName := ctxEntry.AuthInfo

	cluster := cfg.Clusters[clusterName]
	if cluster == nil {
		return nil, fmt.Errorf("kubeconfig cluster %q not found", clusterName)
	}
	apiServerURL := cluster.Server

	authMethod := classifyAuthMethod(cfg, userName)

	restCfg, err := restConfigForContext(kubeconfigPath, contextName)
	if err != nil {
		return nil, err
	}

	// Defensive timeout in case the caller did not set one.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	cs, err := clientset.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	nsList, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	namespaces := make([]string, 0, len(nsList.Items))
	for i := range nsList.Items {
		namespaces = append(namespaces, nsList.Items[i].Name)
	}
	sort.Strings(namespaces)
	namespaceCount := len(namespaces)

	nodes := make([]string, 0, len(nodeList.Items))
	for i := range nodeList.Items {
		nodes = append(nodes, nodeList.Items[i].Name)
	}
	sort.Strings(nodes)
	nodeCount := len(nodes)

	warnings := make([]string, 0)
	clusterVersion := ""
	if version, err := cs.Discovery().ServerVersion(); err != nil {
		warnings = append(warnings, fmt.Sprintf("Cluster version unavailable: %v", err))
	} else if version != nil {
		clusterVersion = version.GitVersion
	}

	serviceAccounts, serviceAccountCount, err := listServiceAccounts(ctx, cs, maxItems)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Service accounts unavailable: %v", err))
	}

	crds, crdCount, err := listCRDs(ctx, restCfg, maxItems)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("CRDs unavailable: %v", err))
	}

	if maxItems > 0 {
		namespaces = limit(namespaces, maxItems)
		nodes = limit(nodes, maxItems)
	}

	return &ClusterFacts{
		APIServerURL:        apiServerURL,
		APIHost:             apiHost(apiServerURL),
		ContextName:         contextName,
		UserName:            userName,
		AuthMethod:          authMethod,
		ClusterVersion:      clusterVersion,
		Namespaces:          namespaces,
		Nodes:               nodes,
		ServiceAccounts:     serviceAccounts,
		CRDs:                crds,
		NamespaceCount:      namespaceCount,
		NodeCount:           nodeCount,
		ServiceAccountCount: serviceAccountCount,
		CRDCount:            crdCount,
		InventoryWarnings:   warnings,
	}, nil
}

func listServiceAccounts(ctx context.Context, cs *clientset.Clientset, maxItems int) ([]string, int, error) {
	saList, err := cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, err
	}
	serviceAccounts := make([]string, 0, len(saList.Items))
	for i := range saList.Items {
		serviceAccounts = append(serviceAccounts, saList.Items[i].Namespace+"/"+saList.Items[i].Name)
	}
	sort.Strings(serviceAccounts)
	count := len(serviceAccounts)
	if maxItems > 0 {
		serviceAccounts = limit(serviceAccounts, maxItems)
	}
	return serviceAccounts, count, nil
}

func listCRDs(ctx context.Context, restCfg *rest.Config, maxItems int) ([]string, int, error) {
	cs, err := apiextensionsclientset.NewForConfig(restCfg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create apiextensions client: %w", err)
	}
	crdList, err := cs.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, err
	}
	crds := make([]string, 0, len(crdList.Items))
	for i := range crdList.Items {
		crds = append(crds, crdList.Items[i].Name)
	}
	sort.Strings(crds)
	count := len(crds)
	if maxItems > 0 {
		crds = limit(crds, maxItems)
	}
	return crds, count, nil
}

func apiHost(apiServerURL string) string {
	u, err := url.Parse(apiServerURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func (f *ClusterFacts) normalize() {
	if f == nil {
		return
	}
	if f.APIHost == "" {
		f.APIHost = apiHost(f.APIServerURL)
	}
	if f.NamespaceCount == 0 && len(f.Namespaces) > 0 {
		f.NamespaceCount = len(f.Namespaces)
	}
	if f.NodeCount == 0 && len(f.Nodes) > 0 {
		f.NodeCount = len(f.Nodes)
	}
	if f.ServiceAccountCount == 0 && len(f.ServiceAccounts) > 0 {
		f.ServiceAccountCount = len(f.ServiceAccounts)
	}
	if f.CRDCount == 0 && len(f.CRDs) > 0 {
		f.CRDCount = len(f.CRDs)
	}
}

func resolveContextName(cfg *clientcmdapi.Config) (string, error) {
	if cfg.CurrentContext != "" {
		return cfg.CurrentContext, nil
	}
	if len(cfg.Contexts) == 1 {
		for name := range cfg.Contexts {
			return name, nil
		}
	}
	if len(cfg.Contexts) == 0 {
		return "", fmt.Errorf("kubeconfig has no contexts")
	}
	// Keep message actionable and consistent with Manager's behavior.
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return "", fmt.Errorf("kubeconfig current-context is not set and multiple contexts are available (%s); set one with 'kubectl config use-context <context-name>'", join(names))
}

func restConfigForContext(kubeconfigPath, contextName string) (*rest.Config, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	clientCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	)
	restCfg, err := clientCfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create rest config: %w", err)
	}
	// Apply a default timeout for all requests made via this rest.Config.
	restCfg.Timeout = 10 * time.Second
	return restCfg, nil
}

func classifyAuthMethod(cfg *clientcmdapi.Config, userName string) string {
	auth := cfg.AuthInfos[userName]
	if auth == nil {
		return "unknown"
	}
	if auth.Exec != nil {
		return "exec"
	}
	if auth.Token != "" || auth.TokenFile != "" {
		return "token"
	}
	if len(auth.ClientCertificateData) > 0 || auth.ClientCertificate != "" {
		return "client-cert"
	}
	if auth.Username != "" && auth.Password != "" {
		return "basic"
	}
	return "unknown"
}

func limit(in []string, max int) []string {
	if max <= 0 || len(in) <= max {
		return in
	}
	out := make([]string, 0, max)
	out = append(out, in[:max]...)
	return out
}

func join(items []string) string {
	if len(items) == 0 {
		return ""
	}
	sep := ", "
	// Manual join avoids pulling in strings for a single call site.
	s := items[0]
	for i := 1; i < len(items); i++ {
		s += sep + items[i]
	}
	return s
}
