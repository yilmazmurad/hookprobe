// Package server listens for webhooks, verifies signatures, stores captures,
// and optionally forwards or replays them.
package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yilmazmurad/hookprobe/internal/capture"
	"github.com/yilmazmurad/hookprobe/internal/signature"
)

// Config controls the local capture listener.
type Config struct {
	Addr          string
	Provider      signature.Provider
	Secret        string
	SaveDir       string
	ForwardURL    string
	AcceptInvalid bool
	Tolerance     time.Duration
	Now           func() time.Time
	Logger        *log.Logger
	Client        *http.Client
	// OnCapture is invoked after a request is recorded (useful in tests).
	OnCapture func(capture.Capture, string)
}

// Handler serves the capture endpoint.
type Handler struct {
	cfg    Config
	client *http.Client
	log    *log.Logger
}

// NewHandler returns an HTTP handler that verifies and records webhooks.
func NewHandler(cfg Config) *Handler {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Tolerance == 0 {
		cfg.Tolerance = signature.DefaultTolerance
	}
	return &Handler{cfg: cfg, client: cfg.Client, log: cfg.Logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	opts := signature.Options{
		Provider:  h.cfg.Provider,
		Secret:    h.cfg.Secret,
		Body:      body,
		Tolerance: h.cfg.Tolerance,
		Now:       h.cfg.Now,
	}
	result := signature.VerifyRequest(opts, r.Header)
	provider := result.Provider
	if provider == "" || provider == signature.ProviderAuto {
		if detected, ok := signature.DetectProvider(r.Header); ok {
			provider = detected
		} else {
			provider = h.cfg.Provider
		}
	}

	rec := capture.New(r, body, provider, result)
	path := ""
	if h.cfg.SaveDir != "" {
		saved, err := rec.WriteFile(h.cfg.SaveDir)
		if err != nil {
			h.log.Printf("save capture: %v", err)
		} else {
			path = saved
		}
	}
	if h.cfg.OnCapture != nil {
		h.cfg.OnCapture(rec, path)
	}

	status := http.StatusOK
	msg := "ok"
	if !result.Valid {
		if h.cfg.AcceptInvalid {
			status = http.StatusAccepted
			msg = "accepted invalid signature: " + result.Reason
		} else {
			status = http.StatusUnauthorized
			msg = "invalid signature: " + result.Reason
		}
	}
	h.log.Printf("%s %s provider=%s valid=%t id=%s %s", r.Method, r.URL.Path, provider, result.Valid, rec.ID, result.Reason)

	if h.cfg.ForwardURL != "" {
		if ferr := h.forward(r.Context(), rec); ferr != nil {
			h.log.Printf("forward: %v", ferr)
			if result.Valid {
				http.Error(w, "forward failed: "+ferr.Error(), http.StatusBadGateway)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

func (h *Handler) forward(ctx context.Context, rec capture.Capture) error {
	_, _, err := Replay(ctx, h.client, rec, h.cfg.ForwardURL, ReplayOptions{})
	return err
}

// ListenAndServe starts the capture server and shuts it down when ctx is cancelled.
func ListenAndServe(ctx context.Context, cfg Config) error {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	handler := NewHandler(cfg)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		err := <-errCh
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// ListenAndServeOn starts the server on an existing listener.
func ListenAndServeOn(ctx context.Context, ln net.Listener, cfg Config) error {
	handler := NewHandler(cfg)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		err := <-errCh
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// ReplayOptions controls how a capture is sent to a target URL.
type ReplayOptions struct {
	Resign    bool
	Secret    string
	Provider  signature.Provider
	Timeout   time.Duration
	Timestamp time.Time
}

// Replay sends a captured webhook to target. When Resign is set, a fresh
// signature is computed for the current (or provided) timestamp so timestamped
// providers accept the replay.
func Replay(ctx context.Context, client *http.Client, rec capture.Capture, target string, opts ReplayOptions) (*http.Response, []byte, error) {
	if target == "" {
		return nil, nil, fmt.Errorf("replay target URL is required")
	}
	if client == nil {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}

	body := rec.BodyBytes()
	req, err := http.NewRequestWithContext(ctx, fallbackMethod(rec.Method), target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	copyHeaders(req.Header, rec.Header())

	if opts.Resign {
		provider := opts.Provider
		if provider == "" || provider == signature.ProviderAuto {
			provider = rec.Provider
		}
		secret := opts.Secret
		if secret == "" {
			return nil, nil, fmt.Errorf("resign requires a webhook secret")
		}
		ts := opts.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		sig, err := signature.Sign(signature.Options{Provider: provider, Secret: secret, Body: body, Timestamp: ts})
		if err != nil {
			return nil, nil, fmt.Errorf("resign: %w", err)
		}
		// Drop previous signature headers so a stale timestamp cannot linger.
		for _, name := range signature.SignatureHeaderNames(provider) {
			req.Header.Del(name)
		}
		if err := signature.ApplySignatureHeaders(req.Header, provider, sig, ts); err != nil {
			return nil, nil, err
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp, nil, err
	}
	return resp, respBody, nil
}

func fallbackMethod(method string) string {
	if strings.TrimSpace(method) == "" {
		return http.MethodPost
	}
	return method
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Host":
		return true
	default:
		return false
	}
}
