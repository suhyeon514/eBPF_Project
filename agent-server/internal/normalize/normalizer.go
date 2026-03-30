package normalize

import (
	"context"
	"fmt"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Normalizer interface {
	Normalize(ctx context.Context, raw model.RawEnvelope) ([]model.Event, error)
}
type Router struct {
	normalizers map[model.RawSource]Normalizer
}

func NewRouter() *Router {
	return &Router{
		normalizers: make(map[model.RawSource]Normalizer),
	}
}

func (r *Router) Register(source model.RawSource, n Normalizer) {
	r.normalizers[source] = n
}

func (r *Router) Normalize(ctx context.Context, raw model.RawEnvelope) ([]model.Event, error) {
	n, ok := r.normalizers[raw.Source]
	if !ok {
		return nil, fmt.Errorf("no normalizer registered for source=%s", raw.Source)
	}
	return n.Normalize(ctx, raw)
}
