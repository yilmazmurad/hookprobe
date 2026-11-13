// Package cli implements the hookprobe command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yilmazmurad/hookprobe/internal/capture"
	"github.com/yilmazmurad/hookprobe/internal/server"
	"github.com/yilmazmurad/hookprobe/internal/signature"
)

// Version is set from main.
var Version = "0.1.0"

const usage = `hookprobe is a zero-dependency CLI for signing, verifying, capturing,
and replaying webhooks from GitHub, Stripe, Slack, or a generic HMAC scheme.

Usage:
  hookprobe <command> [flags]

Commands:
  sign      Create a signature header for a payload
  verify    Verify a signature or request header against a payload
  listen    Start a local capture server that verifies incoming webhooks
  replay    Replay a saved capture to a target URL
  version   Print the hookprobe version
  help      Show this help

Run "hookprobe <command> -h" for command-specific flags.

Examples:
  hookprobe sign --provider github --secret "$HOOK_SECRET" --payload body.json
  hookprobe verify --provider stripe --secret "$HOOK_SECRET" --payload body.json --header "$STRIPE_SIG"
  hookprobe listen --addr :8080 --provider github --secret "$HOOK_SECRET" --save ./captures
  hookprobe replay --file captures/20260101T120000.000000-abcd.json --target http://127.0.0.1:3000/webhook --resign --secret "$HOOK_SECRET"
`

// Run executes the CLI with the given arguments and I/O streams.
// It returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "sign":
		return runSign(rest, stdin, stdout, stderr)
	case "verify":
		return runVerify(rest, stdin, stdout, stderr)
	case "listen":
		return runListen(rest, stdout, stderr)
	case "replay":
		return runReplay(rest, stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "hookprobe %s\n", Version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

func runSign(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts, ok := commonFlags(fs, true)
	if !ok {
		return 2
	}
	jsonOut := fs.Bool("json", false, "print a JSON object instead of the raw signature")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := opts.load(stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sig, err := signature.Sign(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *jsonOut {
		out := map[string]any{
			"provider":  cfg.Provider,
			"signature": sig,
			"timestamp": cfg.Timestamp.Unix(),
		}
		return writeJSON(stdout, stderr, out)
	}
	fmt.Fprintln(stdout, sig)
	if cfg.Provider == signature.ProviderSlack {
		fmt.Fprintf(stderr, "X-Slack-Request-Timestamp: %d\n", cfg.Timestamp.Unix())
	}
	return 0
}

func runVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts, ok := commonFlags(fs, true)
	if !ok {
		return 2
	}
	sigFlag := fs.String("signature", "", "signature value (sha256=..., v0=..., or raw digest)")
	header := fs.String("header", "", "full signature header value (alias of --signature)")
	tsHeader := fs.String("timestamp-header", "", "X-Slack-Request-Timestamp value (if not using --timestamp)")
	jsonOut := fs.Bool("json", false, "print the verification result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := opts.load(stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sigVal := firstNonEmpty(*header, *sigFlag)
	if *tsHeader != "" && cfg.Provider == signature.ProviderSlack {
		result := signature.VerifySlack(cfg.Secret, cfg.Body, sigVal, *tsHeader, cfg.Now(), cfg.Tolerance)
		return emitResult(stdout, stderr, result, *jsonOut)
	}
	result := signature.Verify(cfg, sigVal)
	return emitResult(stdout, stderr, result, *jsonOut)
}

func runListen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	provider := fs.String("provider", "auto", "github, stripe, slack, generic, or auto")
	secret := fs.String("secret", "", "webhook signing secret")
	secretEnv := fs.String("secret-env", "", "environment variable that holds the secret")
	saveDir := fs.String("save", "", "directory to write capture JSON files")
	forward := fs.String("forward", "", "optional URL to forward verified (or accepted) requests to")
	acceptInvalid := fs.Bool("accept-invalid", false, "respond 202 instead of 401 when the signature is invalid")
	tolerance := fs.Duration("tolerance", signature.DefaultTolerance, "allowed clock skew for Stripe/Slack (negative disables the check)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	prov, err := signature.ParseProvider(*provider)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sec, err := resolveSecret(*secret, *secretEnv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(stderr, "listen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "hookprobe listening on http://%s (provider=%s)\n", ln.Addr().String(), prov)
	if *saveDir != "" {
		fmt.Fprintf(stdout, "saving captures to %s\n", *saveDir)
	}
	if *forward != "" {
		fmt.Fprintf(stdout, "forwarding to %s\n", *forward)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = server.ListenAndServeOn(ctx, ln, server.Config{
		Provider:      prov,
		Secret:        sec,
		SaveDir:       *saveDir,
		ForwardURL:    *forward,
		AcceptInvalid: *acceptInvalid,
		Tolerance:     *tolerance,
		Logger:        log.New(stderr, "", log.LstdFlags),
	})
	if err != nil {
		fmt.Fprintf(stderr, "server: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "hookprobe stopped")
	return 0
}

func runReplay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "path to a capture JSON file")
	target := fs.String("target", "", "destination URL")
	resign := fs.Bool("resign", false, "compute a fresh signature before sending")
	secret := fs.String("secret", "", "webhook secret (required with --resign)")
	secretEnv := fs.String("secret-env", "", "environment variable that holds the secret")
	provider := fs.String("provider", "", "override the capture's provider when resigning")
	timeout := fs.Duration("timeout", 10*time.Second, "HTTP client timeout")
	jsonOut := fs.Bool("json", false, "print the HTTP response as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *target == "" {
		fmt.Fprintln(stderr, "replay requires --file and --target")
		return 2
	}
	rec, err := capture.Load(*file)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	opts := server.ReplayOptions{Resign: *resign, Timeout: *timeout}
	if *resign {
		sec, err := resolveSecret(*secret, *secretEnv)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		opts.Secret = sec
		if *provider != "" {
			p, err := signature.ParseProvider(*provider)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			opts.Provider = p
		}
	}
	resp, body, err := server.Replay(context.Background(), nil, rec, *target, opts)
	if err != nil {
		fmt.Fprintf(stderr, "replay: %v\n", err)
		return 1
	}
	if *jsonOut {
		out := map[string]any{
			"status":      resp.StatusCode,
			"status_text": resp.Status,
			"body":        string(body),
			"target":      *target,
			"capture_id":  rec.ID,
		}
		return writeJSON(stdout, stderr, out)
	}
	fmt.Fprintf(stdout, "HTTP %s\n%s", resp.Status, body)
	if len(body) > 0 && !strings.HasSuffix(string(body), "\n") {
		fmt.Fprintln(stdout)
	}
	if resp.StatusCode >= 400 {
		return 1
	}
	return 0
}

type flagOpts struct {
	provider  *string
	secret    *string
	secretEnv *string
	payload   *string
	timestamp *string
	tolerance *time.Duration
	algo      *string
	encoding  *string
}

func commonFlags(fs *flag.FlagSet, requirePayload bool) (flagOpts, bool) {
	_ = requirePayload
	opts := flagOpts{
		provider:  fs.String("provider", "", "github, stripe, slack, or generic"),
		secret:    fs.String("secret", "", "webhook signing secret"),
		secretEnv: fs.String("secret-env", "", "environment variable that holds the secret"),
		payload:   fs.String("payload", "", "payload file path, or - to read stdin"),
		timestamp: fs.String("timestamp", "", "unix seconds or RFC3339 timestamp (Stripe/Slack; default now)"),
		tolerance: fs.Duration("tolerance", signature.DefaultTolerance, "allowed clock skew for Stripe/Slack (negative disables the check)"),
		algo:      fs.String("algo", "sha256", "hmac algorithm for generic (and sha1|sha256 for github)"),
		encoding:  fs.String("encoding", "hex", "digest encoding for generic: hex or base64"),
	}
	return opts, true
}

func (o flagOpts) load(stdin io.Reader) (signature.Options, error) {
	if strings.TrimSpace(*o.provider) == "" {
		return signature.Options{}, fmt.Errorf("--provider is required")
	}
	prov, err := signature.ParseProvider(*o.provider)
	if err != nil {
		return signature.Options{}, err
	}
	if prov == signature.ProviderAuto {
		return signature.Options{}, fmt.Errorf("--provider auto is only valid for listen")
	}
	sec, err := resolveSecret(*o.secret, *o.secretEnv)
	if err != nil {
		return signature.Options{}, err
	}
	body, err := readPayload(*o.payload, stdin)
	if err != nil {
		return signature.Options{}, err
	}
	ts, err := parseTimestamp(*o.timestamp)
	if err != nil {
		return signature.Options{}, err
	}
	algo := signature.Algorithm(strings.ToLower(strings.TrimSpace(*o.algo)))
	enc := signature.Encoding(strings.ToLower(strings.TrimSpace(*o.encoding)))
	nowFn := time.Now
	if !ts.IsZero() {
		nowFn = func() time.Time { return ts }
	}
	return signature.Options{
		Provider:  prov,
		Secret:    sec,
		Body:      body,
		Timestamp: ts,
		Tolerance: *o.tolerance,
		Now:       nowFn,
		Algorithm: algo,
		Encoding:  enc,
	}, nil
}

func readPayload(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("payload is empty (pass --payload FILE or pipe it on stdin)")
		}
		return data, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return data, nil
}

func resolveSecret(direct, envName string) (string, error) {
	if strings.TrimSpace(direct) != "" {
		return direct, nil
	}
	if strings.TrimSpace(envName) != "" {
		val, ok := os.LookupEnv(envName)
		if !ok || val == "" {
			return "", fmt.Errorf("environment variable %s is not set", envName)
		}
		return val, nil
	}
	if val := os.Getenv("HOOKPROBE_SECRET"); val != "" {
		return val, nil
	}
	return "", fmt.Errorf("missing secret (pass --secret, --secret-env, or set HOOKPROBE_SECRET)")
}

func parseTimestamp(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if unix, err := parseUnix(raw); err == nil {
		return time.Unix(unix, 0).UTC(), nil
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid --timestamp %q (want unix seconds or RFC3339)", raw)
}

func parseUnix(raw string) (int64, error) {
	var n int64
	_, err := fmt.Sscan(raw, &n)
	if err != nil {
		return 0, err
	}
	// Reject values that Sscan accepted as a prefix of a non-numeric string.
	if fmt.Sprintf("%d", n) != raw {
		return 0, fmt.Errorf("not an integer")
	}
	return n, nil
}

func emitResult(stdout, stderr io.Writer, result signature.Result, asJSON bool) int {
	if asJSON {
		code := 0
		if !result.Valid {
			code = 1
		}
		if errCode := writeJSON(stdout, stderr, result); errCode != 0 {
			return errCode
		}
		return code
	}
	if result.Valid {
		fmt.Fprintf(stdout, "valid %s signature\n", result.Provider)
		return 0
	}
	fmt.Fprintf(stderr, "invalid %s signature: %s\n", result.Provider, result.Reason)
	return 1
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
