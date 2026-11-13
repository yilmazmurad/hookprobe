package server

import (
	"context"
	"io"
	"net"
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

const secret = "test_webhook_secret"
const payload = `{"hello":"hookprobe"}`

func signedRequest(t *testing.T, provider signature.Provider, ts time.Time) *http.Request {
	t.Helper()
	sig, err := signature.Sign(signature.Options{Provider: provider, Secret: secret, Body: []byte(payload), Timestamp: ts})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	if err := signature.ApplySignatureHeaders(req.Header, provider, sig, ts); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandlerAcceptsValidAndRejectsInvalid(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	var seen []capture.Capture
	h := NewHandler(Config{
		Provider: signature.ProviderGitHub,
		Secret:   secret,
		SaveDir:  dir,
		Now:      func() time.Time { return ts },
		OnCapture: func(c capture.Capture, _ string) {
			seen = append(seen, c)
		},
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, signature.ProviderGitHub, ts))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid status=%d body=%s", rec.Code, rec.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	bad.Header.Set("X-Hub-Signature-256", "sha256=000000")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid status=%d", rec.Code)
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || len(seen) != 2 {
		t.Fatalf("expected two captures, files=%d seen=%d", len(files), len(seen))
	}
}

func TestHandlerAcceptInvalidAndAutoDetect(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	h := NewHandler(Config{
		Provider:      signature.ProviderAuto,
		Secret:        secret,
		AcceptInvalid: true,
		Now:           func() time.Time { return ts },
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, signature.ProviderStripe, ts))
	if rec.Code != http.StatusOK {
		t.Fatalf("auto stripe status=%d body=%s", rec.Code, rec.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("accept-invalid status=%d", rec.Code)
	}
}

func TestHandlerForwardsValidRequests(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	var gotBody []byte
	var gotSig string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Hub-Signature-256")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	h := NewHandler(Config{
		Provider:   signature.ProviderGitHub,
		Secret:     secret,
		ForwardURL: upstream.URL + "/hooks",
		Now:        func() time.Time { return ts },
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, signature.ProviderGitHub, ts))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if string(gotBody) != payload {
		t.Fatalf("forwarded body=%q", gotBody)
	}
	if gotSig == "" {
		t.Fatal("expected forwarded signature header")
	}
}

func TestHandlerForwardFailure(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	h := NewHandler(Config{
		Provider:   signature.ProviderGitHub,
		Secret:     secret,
		ForwardURL: "http://127.0.0.1:1/nope",
		Client:     &http.Client{Timeout: 200 * time.Millisecond},
		Now:        func() time.Time { return ts },
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, signature.ProviderGitHub, ts))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReplayAndResign(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	now := ts.Add(2 * time.Hour)
	var gotTS, gotBody string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTS = r.Header.Get("Stripe-Signature")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("replayed"))
	}))
	defer target.Close()

	oldSig := signature.SignStripe(secret, []byte(payload), ts)
	rec := capture.Capture{
		Method:   http.MethodPost,
		Provider: signature.ProviderStripe,
		Headers:  map[string][]string{"Stripe-Signature": {oldSig}, "Content-Type": {"application/json"}},
		Body:     payload,
	}

	// Without resign, we just deliver the original (possibly expired) header.
	resp, body, err := Replay(context.Background(), nil, rec, target.URL, ReplayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "replayed" || gotBody != payload {
		t.Fatalf("replay status=%d body=%q gotBody=%q", resp.StatusCode, body, gotBody)
	}

	resp, _, err = Replay(context.Background(), nil, rec, target.URL, ReplayOptions{
		Resign:    true,
		Secret:    secret,
		Timestamp: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resign status=%d", resp.StatusCode)
	}
	want := signature.SignStripe(secret, []byte(payload), now)
	if gotTS != want {
		t.Fatalf("resigned header=%q want %q", gotTS, want)
	}
	if result := signature.VerifyStripe(secret, []byte(payload), gotTS, now, signature.DefaultTolerance); !result.Valid {
		t.Fatalf("resigned signature should verify: %+v", result)
	}

	if _, _, err := Replay(context.Background(), nil, rec, "", ReplayOptions{}); err == nil {
		t.Fatal("empty target should fail")
	}
	if _, _, err := Replay(context.Background(), nil, rec, target.URL, ReplayOptions{Resign: true}); err == nil {
		t.Fatal("resign without secret should fail")
	}
}

func TestListenAndServeOnShutdown(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- ListenAndServeOn(ctx, ln, Config{Provider: signature.ProviderGitHub, Secret: secret})
	}()

	ts := time.Now()
	sig, err := signature.SignGitHub(secret, []byte(payload), signature.AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/webhook", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature-256", sig)
	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
		req, _ = http.NewRequest(http.MethodPost, "http://"+addr+"/webhook", strings.NewReader(payload))
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	_ = ts
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("shutdown error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestReplaySavesAndLoadsFromDisk(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	dir := t.TempDir()
	h := NewHandler(Config{Provider: signature.ProviderSlack, Secret: secret, SaveDir: dir, Now: func() time.Time { return ts }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(t, signature.ProviderSlack, ts))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	loaded, err := capture.Load(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Verification.Valid || loaded.Provider != signature.ProviderSlack {
		t.Fatalf("loaded=%+v", loaded)
	}
}
