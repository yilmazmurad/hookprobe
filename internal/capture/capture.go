// Package capture stores and reloads recorded webhook requests.
package capture

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yilmazmurad/hookprobe/internal/signature"
)

// Capture is a recorded webhook delivery that can be inspected or replayed.
type Capture struct {
	ID           string              `json:"id"`
	ReceivedAt   time.Time           `json:"received_at"`
	Provider     signature.Provider  `json:"provider"`
	Method       string              `json:"method"`
	Path         string              `json:"path"`
	URL          string              `json:"url,omitempty"`
	RemoteAddr   string              `json:"remote_addr,omitempty"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	Verification signature.Result    `json:"verification"`
}

// New builds a capture from an incoming HTTP request and its already-read body.
func New(r *http.Request, body []byte, provider signature.Provider, result signature.Result) Capture {
	headers := make(map[string][]string, len(r.Header))
	for k, vals := range r.Header {
		copied := make([]string, len(vals))
		copy(copied, vals)
		headers[k] = copied
	}
	path := r.URL.RequestURI()
	if path == "" {
		path = r.URL.Path
	}
	return Capture{
		ID:           newID(),
		ReceivedAt:   time.Now().UTC(),
		Provider:     provider,
		Method:       r.Method,
		Path:         path,
		URL:          r.URL.String(),
		RemoteAddr:   r.RemoteAddr,
		Headers:      headers,
		Body:         string(body),
		Verification: result,
	}
}

// Header returns the capture as an http.Header.
func (c Capture) Header() http.Header {
	h := make(http.Header, len(c.Headers))
	for k, vals := range c.Headers {
		copied := make([]string, len(vals))
		copy(copied, vals)
		h[k] = copied
	}
	return h
}

// BodyBytes returns the captured payload.
func (c Capture) BodyBytes() []byte {
	return []byte(c.Body)
}

// WriteFile stores the capture as pretty-printed JSON in dir and returns the path.
func (c Capture) WriteFile(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("capture directory is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create capture directory: %w", err)
	}
	name := fmt.Sprintf("%s-%s.json", c.ReceivedAt.UTC().Format("20060102T150405.000000"), c.ID)
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write capture: %w", err)
	}
	return path, nil
}

// Load reads a capture JSON file from path.
func Load(path string) (Capture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Capture{}, fmt.Errorf("read capture: %w", err)
	}
	var c Capture
	if err := json.Unmarshal(data, &c); err != nil {
		return Capture{}, fmt.Errorf("parse capture %s: %w", path, err)
	}
	if c.ID == "" && c.Body == "" && c.Method == "" {
		return Capture{}, fmt.Errorf("parse capture %s: missing required fields", path)
	}
	return c, nil
}

// List returns capture files in dir, newest first.
func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(strings.ToLower(name), ".json") {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] > paths[j] })
	return paths, nil
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
