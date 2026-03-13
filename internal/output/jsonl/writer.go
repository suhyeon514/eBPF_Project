package jsonl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/suhyeon514/eBPF_Project/internal/model"
)

type Writer struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func New(path string) (*Writer, error) {
	if path == "" {
		return nil, fmt.Errorf("jsonl writer path is empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open json file: %w", err)
	}

	return &Writer{
		path: path,
		f:    f,
	}, nil
}

func (w *Writer) Path() string {
	return w.path
}

func (w *Writer) WriteEvent(ev model.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	b = append(b, '\n')

	if _, err := w.f.Write(b); err != nil {
		return fmt.Errorf("write event: %w", err)
	}

	return nil
}

func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("sync jsonl file: %w", err)
	}
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.f == nil {
		return nil
	}
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("close jsonl file: %w", err)
	}
	w.f = nil
	return nil
}
