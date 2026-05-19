package guardian

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Auditor struct {
	mu   sync.Mutex
	path string
}

func NewAuditor(dir string) (*Auditor, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, fmt.Sprintf("guardian-%s.jsonl", time.Now().Format("20060102")))
	return &Auditor{path: path}, nil
}

func (a *Auditor) Write(record AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	fh, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fh.Close()
	b, _ := json.Marshal(record)
	_, err = fh.Write(append(b, '\n'))
	return err
}

func (a *Auditor) Path() string { return a.path }
