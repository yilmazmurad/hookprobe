// Package signature signs and verifies webhook payloads for common providers
// using only the Go standard library.
package signature

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"strings"
	"time"
)

// Provider identifies a webhook signature scheme.
type Provider string

const (
	ProviderGitHub  Provider = "github"
	ProviderStripe  Provider = "stripe"
	ProviderSlack   Provider = "slack"
	ProviderGeneric Provider = "generic"
	ProviderAuto    Provider = "auto"
)

// Algorithm is an HMAC hash algorithm.
type Algorithm string

const (
	AlgoSHA1   Algorithm = "sha1"
	AlgoSHA256 Algorithm = "sha256"
	AlgoSHA512 Algorithm = "sha512"
)

// Encoding is how the HMAC digest is rendered in a header.
type Encoding string

const (
	EncodingHex    Encoding = "hex"
	EncodingBase64 Encoding = "base64"
)

// DefaultTolerance is the default clock-skew window for timestamped providers.
const DefaultTolerance = 5 * time.Minute

// Options controls signing and verification.
type Options struct {
	Provider  Provider
	Secret    string
	Body      []byte
	Timestamp time.Time
	// Tolerance is the allowed clock skew for Stripe and Slack. A negative
	// value disables the timestamp check. The zero value means DefaultTolerance.
	Tolerance time.Duration
	Now       func() time.Time
	// Algorithm and Encoding apply to the generic provider, and Algorithm
	// also selects GitHub's sha1 vs sha256 scheme (default sha256).
	Algorithm Algorithm
	Encoding  Encoding
}

// Result is the outcome of a verification attempt.
type Result struct {
	Valid     bool      `json:"valid"`
	Provider  Provider  `json:"provider"`
	Algorithm Algorithm `json:"algorithm,omitempty"`
	Signature string    `json:"signature,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// ParseProvider normalizes a provider name.
func ParseProvider(name string) (Provider, error) {
	switch Provider(strings.ToLower(strings.TrimSpace(name))) {
	case ProviderGitHub:
		return ProviderGitHub, nil
	case ProviderStripe:
		return ProviderStripe, nil
	case ProviderSlack:
		return ProviderSlack, nil
	case ProviderGeneric:
		return ProviderGeneric, nil
	case ProviderAuto, "":
		return ProviderAuto, nil
	default:
		return "", fmt.Errorf("unknown provider %q (want github, stripe, slack, generic, or auto)", name)
	}
}

// DetectProvider infers a provider from request headers.
func DetectProvider(h http.Header) (Provider, bool) {
	switch {
	case headerGet(h, "Stripe-Signature") != "":
		return ProviderStripe, true
	case headerGet(h, "X-Slack-Signature") != "" || headerGet(h, "X-Slack-Request-Timestamp") != "":
		return ProviderSlack, true
	case headerGet(h, "X-Hub-Signature-256") != "" || headerGet(h, "X-Hub-Signature") != "":
		return ProviderGitHub, true
	default:
		return "", false
	}
}

// SignatureHeaderNames returns the header names a provider uses for verification.
func SignatureHeaderNames(p Provider) []string {
	switch p {
	case ProviderGitHub:
		return []string{"X-Hub-Signature-256", "X-Hub-Signature"}
	case ProviderStripe:
		return []string{"Stripe-Signature"}
	case ProviderSlack:
		return []string{"X-Slack-Signature", "X-Slack-Request-Timestamp"}
	default:
		return nil
	}
}

// Sign produces the signature header value for the given options.
func Sign(opts Options) (string, error) {
	if err := validateSecret(opts.Secret); err != nil {
		return "", err
	}
	opts = normalize(opts)
	switch opts.Provider {
	case ProviderGitHub:
		return SignGitHub(opts.Secret, opts.Body, opts.Algorithm)
	case ProviderStripe:
		return SignStripe(opts.Secret, opts.Body, opts.Timestamp), nil
	case ProviderSlack:
		return SignSlack(opts.Secret, opts.Body, opts.Timestamp), nil
	case ProviderGeneric:
		return SignGeneric(opts.Secret, opts.Body, opts.Algorithm, opts.Encoding)
	case ProviderAuto:
		return "", fmt.Errorf("provider auto cannot be used with sign; specify github, stripe, slack, or generic")
	default:
		return "", fmt.Errorf("unknown provider %q", opts.Provider)
	}
}

// Verify checks a signature or raw header value against the payload.
func Verify(opts Options, signature string) Result {
	if err := validateSecret(opts.Secret); err != nil {
		return Result{Provider: opts.Provider, Reason: err.Error()}
	}
	if strings.TrimSpace(signature) == "" {
		return Result{Provider: opts.Provider, Reason: "missing signature"}
	}
	opts = normalize(opts)
	switch opts.Provider {
	case ProviderGitHub:
		return VerifyGitHub(opts.Secret, opts.Body, signature)
	case ProviderStripe:
		return VerifyStripe(opts.Secret, opts.Body, signature, opts.now(), opts.Tolerance)
	case ProviderSlack:
		return VerifySlack(opts.Secret, opts.Body, signature, timestampString(opts.Timestamp), opts.now(), opts.Tolerance)
	case ProviderGeneric:
		return VerifyGeneric(opts.Secret, opts.Body, signature, opts.Algorithm, opts.Encoding)
	default:
		return Result{Provider: opts.Provider, Reason: fmt.Sprintf("unknown provider %q", opts.Provider)}
	}
}

// VerifyRequest extracts the relevant headers from an HTTP request and verifies them.
func VerifyRequest(opts Options, h http.Header) Result {
	if opts.Provider == ProviderAuto || opts.Provider == "" {
		detected, ok := DetectProvider(h)
		if !ok {
			return Result{Provider: ProviderAuto, Reason: "unable to detect provider from headers"}
		}
		opts.Provider = detected
	}
	switch opts.Provider {
	case ProviderGitHub:
		sig := headerGet(h, "X-Hub-Signature-256")
		if sig == "" {
			sig = headerGet(h, "X-Hub-Signature")
		}
		return Verify(opts, sig)
	case ProviderStripe:
		return Verify(opts, headerGet(h, "Stripe-Signature"))
	case ProviderSlack:
		opts = normalize(opts)
		return VerifySlack(opts.Secret, opts.Body, headerGet(h, "X-Slack-Signature"), headerGet(h, "X-Slack-Request-Timestamp"), opts.now(), opts.Tolerance)
	case ProviderGeneric:
		return Result{Provider: ProviderGeneric, Reason: "generic provider requires --signature or --header; cannot auto-detect a header name"}
	default:
		return Result{Provider: opts.Provider, Reason: fmt.Sprintf("unknown provider %q", opts.Provider)}
	}
}

// ApplySignatureHeaders writes the provider's signature headers onto h.
func ApplySignatureHeaders(h http.Header, provider Provider, signature string, ts time.Time) error {
	switch provider {
	case ProviderGitHub:
		if strings.HasPrefix(signature, "sha1=") {
			h.Set("X-Hub-Signature", signature)
			return nil
		}
		h.Set("X-Hub-Signature-256", signature)
		return nil
	case ProviderStripe:
		h.Set("Stripe-Signature", signature)
		return nil
	case ProviderSlack:
		h.Set("X-Slack-Signature", signature)
		h.Set("X-Slack-Request-Timestamp", timestampString(ts))
		return nil
	case ProviderGeneric:
		h.Set("X-Signature", signature)
		return nil
	default:
		return fmt.Errorf("unknown provider %q", provider)
	}
}

func validateSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("missing webhook secret")
	}
	return nil
}

func normalize(opts Options) Options {
	if opts.Algorithm == "" {
		opts.Algorithm = AlgoSHA256
	}
	if opts.Encoding == "" {
		opts.Encoding = EncodingHex
	}
	if opts.Timestamp.IsZero() {
		opts.Timestamp = time.Now()
	}
	if opts.Tolerance == 0 {
		opts.Tolerance = DefaultTolerance
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func (opts Options) now() time.Time {
	if opts.Now != nil {
		return opts.Now()
	}
	return time.Now()
}

func timestampString(ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	return fmt.Sprintf("%d", ts.Unix())
}

func newHash(algo Algorithm) (func() hash.Hash, error) {
	switch algo {
	case AlgoSHA1:
		return sha1.New, nil
	case AlgoSHA256, "":
		return sha256.New, nil
	case AlgoSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q (want sha1, sha256, or sha512)", algo)
	}
}

func hmacSum(secret string, body []byte, algo Algorithm, enc Encoding) (string, error) {
	hf, err := newHash(algo)
	if err != nil {
		return "", err
	}
	mac := hmac.New(hf, []byte(secret))
	if _, err := mac.Write(body); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	switch enc {
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString(sum), nil
	case EncodingHex, "":
		return hex.EncodeToString(sum), nil
	default:
		return "", fmt.Errorf("unsupported encoding %q (want hex or base64)", enc)
	}
}

func compareDigest(got, want string) bool {
	return hmac.Equal([]byte(got), []byte(want))
}

func headerGet(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	return strings.TrimSpace(h.Get(name))
}
