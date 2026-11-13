package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yilmazmurad/hookprobe/internal/capture"
	"github.com/yilmazmurad/hookprobe/internal/signature"
)

func run(args ...string) (int, string, string) {
	return runWithStdin("", args...)
}

func runWithStdin(stdin string, args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &err)
	return code, out.String(), err.String()
}

func TestHelpAndVersion(t *testing.T) {
	t.Parallel()
	code, out, _ := run("help")
	if code != 0 || !strings.Contains(out, "hookprobe is a zero-dependency CLI") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}
	code, out, err := run()
	if code != 2 || !strings.Contains(err, "Usage:") {
		t.Fatalf("no args: code=%d err=%q", code, err)
	}
	code, out, _ = run("version")
	if code != 0 || !strings.Contains(out, "hookprobe") {
		t.Fatalf("version: %d %q", code, out)
	}
	code, _, err = run("nope")
	if code != 2 || !strings.Contains(err, "unknown command") {
		t.Fatalf("unknown: %d %q", code, err)
	}
}

func TestSignVerifyGitHubFromFileAndStdin(t *testing.T) {
	t.Setenv("HOOKPROBE_SECRET", "")
	dir := t.TempDir()
	payload := filepath.Join(dir, "body.json")
	if err := os.WriteFile(payload, []byte(`{"action":"opened"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, sig, err := run("sign", "--provider", "github", "--secret", "s3cret", "--payload", payload)
	if code != 0 {
		t.Fatalf("sign failed: %d %s", code, err)
	}
	sig = strings.TrimSpace(sig)
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("signature=%q", sig)
	}
	code, out, err := run("verify", "--provider", "github", "--secret", "s3cret", "--payload", payload, "--signature", sig)
	if code != 0 {
		t.Fatalf("verify failed: %d %s %s", code, out, err)
	}
	if !strings.Contains(out, "valid github signature") {
		t.Fatalf("out=%q", out)
	}

	code, sig, err = runWithStdin(`{"action":"opened"}`, "sign", "--provider", "github", "--secret", "s3cret", "--payload", "-", "--json")
	if code != 0 {
		t.Fatalf("sign stdin/json: %d %s", code, err)
	}
	var payloadJSON map[string]any
	if e := json.Unmarshal([]byte(sig), &payloadJSON); e != nil {
		t.Fatal(e)
	}
	if payloadJSON["provider"] != "github" || payloadJSON["signature"] == "" {
		t.Fatalf("json=%v", payloadJSON)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	t.Setenv("HOOKPROBE_SECRET", "")
	dir := t.TempDir()
	payload := filepath.Join(dir, "body.json")
	if err := os.WriteFile(payload, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, sig, errOut := run("sign", "--provider", "generic", "--secret", "k", "--payload", payload)
	if strings.TrimSpace(errOut) != "" && !strings.Contains(sig, "\n") {
		// sign should succeed
	}
	sig = strings.TrimSpace(sig)
	if err := os.WriteFile(payload, []byte(`{"ok":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, err := run("verify", "--provider", "generic", "--secret", "k", "--payload", payload, "--signature", sig, "--json")
	if code != 1 {
		t.Fatalf("expected failure, code=%d err=%s", code, err)
	}
}

func TestStripeAndSlackWithTimestamp(t *testing.T) {
	t.Setenv("HOOKPROBE_SECRET", "")
	dir := t.TempDir()
	payload := filepath.Join(dir, "evt.json")
	body := []byte(`{"type":"invoice.paid"}`)
	if err := os.WriteFile(payload, body, 0o644); err != nil {
		t.Fatal(err)
	}
	ts := "1700000000"

	code, sig, err := run("sign", "--provider", "stripe", "--secret", "whsec", "--payload", payload, "--timestamp", ts)
	if code != 0 {
		t.Fatalf("stripe sign: %d %s", code, err)
	}
	code, out, err := run("verify", "--provider", "stripe", "--secret", "whsec", "--payload", payload, "--header", strings.TrimSpace(sig), "--timestamp", ts)
	if code != 0 {
		t.Fatalf("stripe verify: %d %s %s", code, out, err)
	}

	code, sig, err = run("sign", "--provider", "slack", "--secret", "slacksec", "--payload", payload, "--timestamp", ts)
	if code != 0 {
		t.Fatalf("slack sign: %d %s", code, err)
	}
	code, out, err = run("verify", "--provider", "slack", "--secret", "slacksec", "--payload", payload, "--signature", strings.TrimSpace(sig), "--timestamp-header", ts, "--timestamp", ts)
	if code != 0 {
		t.Fatalf("slack verify: %d %s %s", code, out, err)
	}
}

func TestSecretEnvAndValidationErrors(t *testing.T) {
	t.Setenv("HOOKPROBE_SECRET", "")
	t.Setenv("MY_HOOK_SECRET", "from-env")
	dir := t.TempDir()
	payload := filepath.Join(dir, "p.json")
	if err := os.WriteFile(payload, []byte("ping"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, sig, err := run("sign", "--provider", "github", "--secret-env", "MY_HOOK_SECRET", "--payload", payload)
	if code != 0 {
		t.Fatalf("secret-env: %d %s", code, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(sig), "sha256=") {
		t.Fatalf("sig=%q", sig)
	}

	code, _, err = run("sign", "--provider", "github", "--payload", payload)
	if code != 2 || !strings.Contains(err, "missing secret") {
		t.Fatalf("missing secret: %d %s", code, err)
	}
	code, _, err = run("sign", "--secret", "x", "--payload", payload)
	if code != 2 || !strings.Contains(err, "--provider is required") {
		t.Fatalf("missing provider: %d %s", code, err)
	}
	code, _, err = run("sign", "--provider", "auto", "--secret", "x", "--payload", payload)
	if code != 2 || !strings.Contains(err, "only valid for listen") {
		t.Fatalf("auto sign: %d %s", code, err)
	}
	code, _, err = run("verify", "--provider", "nope", "--secret", "x", "--payload", payload, "--signature", "sha256=ab")
	if code != 2 || !strings.Contains(err, "unknown provider") {
		t.Fatalf("bad provider: %d %s", code, err)
	}
	code, _, err = run("sign", "--provider", "github", "--secret", "x", "--payload", filepath.Join(dir, "missing.json"))
	if code != 2 || !strings.Contains(err, "read payload") {
		t.Fatalf("missing payload: %d %s", code, err)
	}
	code, _, err = runWithStdin("", "sign", "--provider", "github", "--secret", "x")
	if code != 2 || !strings.Contains(err, "payload is empty") {
		t.Fatalf("empty stdin: %d %s", code, err)
	}
	code, _, err = run("listen", "--provider", "github")
	if code != 2 || !strings.Contains(err, "missing secret") {
		t.Fatalf("listen missing secret: %d %s", code, err)
	}
	code, _, err = run("replay")
	if code != 2 || !strings.Contains(err, "--file and --target") {
		t.Fatalf("replay usage: %d %s", code, err)
	}
}

func TestReplayCommand(t *testing.T) {
	t.Setenv("HOOKPROBE_SECRET", "")
	var got string
	ts := time.Unix(1_700_000_000, 0).UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Hub-Signature-256")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	body := []byte(`{"ping":true}`)
	sig, err := signature.SignGitHub("s3cret", body, signature.AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	rec := capture.Capture{
		ID:       "abc123",
		Method:   http.MethodPost,
		Provider: signature.ProviderGitHub,
		Headers:  map[string][]string{"X-Hub-Signature-256": {sig}},
		Body:     string(body),
	}
	dir := t.TempDir()
	path, err := rec.WriteFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = ts
	code, out, errOut := run("replay", "--file", path, "--target", srv.URL+"/hook", "--json")
	if code != 0 {
		t.Fatalf("replay: %d %s %s", code, out, errOut)
	}
	if got != sig {
		t.Fatalf("target got signature %q", got)
	}
	if !strings.Contains(out, `"status": 200`) && !strings.Contains(out, `"status":200`) {
		t.Fatalf("json out=%s", out)
	}

	code, _, errOut = run("replay", "--file", path, "--target", srv.URL, "--resign")
	if code != 2 || !strings.Contains(errOut, "missing secret") {
		t.Fatalf("resign without secret: %d %s", code, errOut)
	}
}

func TestParseTimestamp(t *testing.T) {
	t.Parallel()
	ts, err := parseTimestamp("1700000000")
	if err != nil || ts.Unix() != 1_700_000_000 {
		t.Fatalf("unix: %v %v", ts, err)
	}
	ts, err = parseTimestamp("2023-11-14T22:13:20Z")
	if err != nil || ts.Unix() != 1_700_000_000 {
		t.Fatalf("rfc3339: %v %v", ts, err)
	}
	if _, err := parseTimestamp("not-a-date"); err == nil {
		t.Fatal("expected error")
	}
	ts, err = parseTimestamp("")
	if err != nil || !ts.IsZero() {
		t.Fatalf("empty: %v %v", ts, err)
	}
}
