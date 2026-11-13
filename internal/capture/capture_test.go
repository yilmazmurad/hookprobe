package capture

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yilmazmurad/hookprobe/internal/signature"
)

func TestNewWriteLoadRoundTrip(t *testing.T) {
	t.Parallel()
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/webhook?x=1", nil)
	req.Header.Set("X-Hub-Signature-256", "sha256=abc")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1234"
	result := signature.Result{Valid: true, Provider: signature.ProviderGitHub, Algorithm: signature.AlgoSHA256}
	c := New(req, body, signature.ProviderGitHub, result)

	if c.ID == "" {
		t.Fatal("expected capture id")
	}
	if c.Method != http.MethodPost {
		t.Fatalf("method=%q", c.Method)
	}
	if c.Path != "/webhook?x=1" {
		t.Fatalf("path=%q", c.Path)
	}
	if c.Body != string(body) {
		t.Fatalf("body=%q", c.Body)
	}
	if c.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers=%v", c.Header())
	}
	if string(c.BodyBytes()) != string(body) {
		t.Fatal("BodyBytes mismatch")
	}

	dir := t.TempDir()
	path, err := c.WriteFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".json" {
		t.Fatalf("path=%s", path)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != c.ID || loaded.Body != c.Body || loaded.Provider != c.Provider {
		t.Fatalf("loaded mismatch: %+v vs %+v", loaded, c)
	}
	if !loaded.Verification.Valid {
		t.Fatalf("verification: %+v", loaded.Verification)
	}
}

func TestWriteFileEmptyDirAndLoadErrors(t *testing.T) {
	t.Parallel()
	var c Capture
	if _, err := c.WriteFile(""); err == nil {
		t.Fatal("empty dir should fail")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file should fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Fatal("invalid json should fail")
	}
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(empty); err == nil {
		t.Fatal("empty capture should fail")
	}
}

func TestListNewestFirst(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"a","method":"POST","body":"{}"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"id":"b","method":"POST","body":"{}"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("got %v", paths)
	}
	if !strings.HasSuffix(paths[0], "b.json") || !strings.HasSuffix(paths[1], "a.json") {
		t.Fatalf("expected newest-name-first lexical order, got %v", paths)
	}
}
