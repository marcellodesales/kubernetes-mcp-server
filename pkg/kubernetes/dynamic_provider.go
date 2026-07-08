package kubernetes

import (
	"context"
	"errors"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ErrProviderNotConfigured is returned when a cluster-scoped operation is
// attempted before a real provider has been configured.
var ErrProviderNotConfigured = errors.New("kubernetes provider is not configured; visit /kube/login")

// DynamicProvider starts "unconfigured" and can be swapped to a real Provider at
// runtime. It is used by the bootstrap UI flow to ensure the server does not
// connect to Kubernetes until a kubeconfig has been selected/validated.
type DynamicProvider struct {
	mu sync.RWMutex

	p Provider

	watchCtx    context.Context
	watchReload McpReload
}

var _ Provider = (*DynamicProvider)(nil)

func NewDynamicProvider() *DynamicProvider {
	return &DynamicProvider{}
}

// IsConfigured reports whether a real Provider has been installed.
func (d *DynamicProvider) IsConfigured() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p != nil
}

// SetProvider installs p as the active provider. Any previously installed
// provider is closed.
func (d *DynamicProvider) SetProvider(p Provider) {
	d.mu.Lock()
	old := d.p
	d.p = p
	watchCtx := d.watchCtx
	watchReload := d.watchReload
	d.mu.Unlock()

	if old != nil && old != p {
		old.Close()
	}
	if p != nil && watchCtx != nil && watchReload != nil {
		p.WatchTargets(watchCtx, watchReload)
	}
}

func (d *DynamicProvider) provider() Provider {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p
}

func (d *DynamicProvider) IsOpenShift(ctx context.Context) bool {
	if p := d.provider(); p != nil {
		return p.IsOpenShift(ctx)
	}
	return false
}

func (d *DynamicProvider) IsMultiTarget() bool {
	if p := d.provider(); p != nil {
		return p.IsMultiTarget()
	}
	return false
}

func (d *DynamicProvider) GetTargets(ctx context.Context) ([]string, error) {
	if p := d.provider(); p != nil {
		return p.GetTargets(ctx)
	}
	return nil, ErrProviderNotConfigured
}

func (d *DynamicProvider) GetDerivedKubernetes(ctx context.Context, target string) (*Kubernetes, error) {
	if p := d.provider(); p != nil {
		return p.GetDerivedKubernetes(ctx, target)
	}
	return nil, ErrProviderNotConfigured
}

func (d *DynamicProvider) GetDefaultTarget() string {
	if p := d.provider(); p != nil {
		return p.GetDefaultTarget()
	}
	return ""
}

func (d *DynamicProvider) GetTargetParameterName() string {
	if p := d.provider(); p != nil {
		return p.GetTargetParameterName()
	}
	return ""
}

func (d *DynamicProvider) WatchTargets(ctx context.Context, reload McpReload) {
	d.mu.Lock()
	d.watchCtx = ctx
	d.watchReload = reload
	p := d.p
	d.mu.Unlock()

	if p != nil {
		p.WatchTargets(ctx, reload)
	}
}

func (d *DynamicProvider) Close() {
	d.mu.Lock()
	p := d.p
	d.p = nil
	d.mu.Unlock()

	if p != nil {
		p.Close()
	}
}

func (d *DynamicProvider) HasGVKs(ctx context.Context, gvks []schema.GroupVersionKind) bool {
	if p := d.provider(); p != nil {
		return p.HasGVKs(ctx, gvks)
	}
	// Providers that have not opted in to discovery should return true so tools
	// remain visible; the unconfigured provider follows that convention.
	return true
}
