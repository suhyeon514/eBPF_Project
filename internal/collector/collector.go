package collector

import (
	"context"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Collector interface {
	Name() string

	Start(ctx context.Context) error

	Events() <-chan model.RawEnvelope

	Errors() <-chan error

	Stop(ctx context.Context) error
}
