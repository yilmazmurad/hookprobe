package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testSecret = "whsec_test_secret_value"
const testBody = `{"id":"evt_1","type":"checkout.session.completed"}`

func TestParseProvider(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    Provider
		wantErr bool
	}{
		{"github", ProviderGitHub, false},
		{" GitHub ", ProviderGitHub, false},
		{"STRIPE", ProviderStripe, false},
		{"slack", ProviderSlack, false},
		{"generic", ProviderGeneric, false},
		{"auto", ProviderAuto, false},
		{"", ProviderAuto, false},
		{"paypal", "", true},
	}
	for _, tc := range cases {
		got, err := ParseProvider(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseProvider(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseProvider(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseProvider(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGitHubSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	for _, algo := range []Algorithm{AlgoSHA256, AlgoSHA1} {
		sig, err := SignGitHub(testSecret, []byte(testBody), algo)
		if err != nil {
			t.Fatalf("SignGitHub(%s): %v", algo, err)
		}
		if !strings.HasPrefix(sig, string(algo)+"=") {
			t.Fatalf("signature %q missing prefix %s=", sig, algo)
		}
		got := VerifyGitHub(testSecret, []byte(testBody), sig)
		if !got.Valid {
			t.Fatalf("expected valid %s signature, got %+v", algo, got)
		}
		if got.Algorithm != algo {
			t.Fatalf("algorithm=%q, want %q", got.Algorithm, algo)
		}
	}
}

func TestGitHubRejectsTampering(t *testing.T) {
	t.Parallel()
	sig, err := SignGitHub(testSecret, []byte(testBody), AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		body string
		sig  string
		sec  string
	}{
		{"tampered body", testBody + " ", sig, testSecret},
		{"wrong secret", testBody, sig, testSecret + "x"},
		{"truncated sig", testBody, sig[:len(sig)-2], testSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyGitHub(tc.sec, []byte(tc.body), tc.sig)
			if got.Valid {
				t.Fatalf("expected invalid, got %+v", got)
			}
			if got.Reason == "" {
				t.Fatal("expected a rejection reason")
			}
		})
	}
}

func TestGitHubInvalidHeader(t *testing.T) {
	t.Parallel()
	for _, header := range []string{"", "sha256", "md5=abcd", "sha256="} {
		got := VerifyGitHub(testSecret, []byte(testBody), header)
		if got.Valid {
			t.Fatalf("header %q should be invalid", header)
		}
	}
}

func TestStripeSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	sig := SignStripe(testSecret, []byte(testBody), ts)
	if !strings.HasPrefix(sig, "t=1700000000,v1=") {
		t.Fatalf("unexpected stripe header %q", sig)
	}
	got := VerifyStripe(testSecret, []byte(testBody), sig, ts, DefaultTolerance)
	if !got.Valid {
		t.Fatalf("expected valid stripe signature, got %+v", got)
	}
	if !got.Timestamp.Equal(ts) {
		t.Fatalf("timestamp=%v, want %v", got.Timestamp, ts)
	}
}

func TestStripeAcceptsRotatedSecrets(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	current := SignStripe(testSecret, []byte(testBody), ts)
	old := SignStripe("old_secret", []byte(testBody), ts)
	_, oldV1, _ := strings.Cut(old, "v1=")
	// Header carries both the current and previous v1 values, as Stripe does
	// during secret rotation.
	combined := current + ",v1=" + oldV1
	got := VerifyStripe(testSecret, []byte(testBody), combined, ts, DefaultTolerance)
	if !got.Valid {
		t.Fatalf("expected match against one of multiple v1 values, got %+v", got)
	}
}

func TestStripeTimestampTolerance(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	sig := SignStripe(testSecret, []byte(testBody), ts)

	expired := VerifyStripe(testSecret, []byte(testBody), sig, ts.Add(6*time.Minute), DefaultTolerance)
	if expired.Valid || !strings.Contains(expired.Reason, "tolerance") {
		t.Fatalf("expected tolerance rejection, got %+v", expired)
	}

	skipped := VerifyStripe(testSecret, []byte(testBody), sig, ts.Add(24*time.Hour), -1)
	if !skipped.Valid {
		t.Fatalf("negative tolerance should skip the window check, got %+v", skipped)
	}

	within := VerifyStripe(testSecret, []byte(testBody), sig, ts.Add(4*time.Minute), DefaultTolerance)
	if !within.Valid {
		t.Fatalf("4 minutes should be inside the window, got %+v", within)
	}
}

func TestStripeRejectsTampering(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	sig := SignStripe(testSecret, []byte(testBody), ts)
	got := VerifyStripe(testSecret, []byte(testBody+"x"), sig, ts, DefaultTolerance)
	if got.Valid {
		t.Fatal("tampered body should fail")
	}
}

func TestStripeInvalidHeader(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	for _, header := range []string{"", "v1=abcd", "t=notanumber,v1=abcd", "t=123"} {
		got := VerifyStripe(testSecret, []byte(testBody), header, ts, DefaultTolerance)
		if got.Valid {
			t.Fatalf("header %q should be invalid", header)
		}
	}
}

func TestSlackSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	sig := SignSlack(testSecret, []byte(testBody), ts)
	if !strings.HasPrefix(sig, "v0=") {
		t.Fatalf("unexpected slack signature %q", sig)
	}
	got := VerifySlack(testSecret, []byte(testBody), sig, "1700000000", ts, DefaultTolerance)
	if !got.Valid {
		t.Fatalf("expected valid slack signature, got %+v", got)
	}
}

func TestSlackTimestampToleranceAndTamper(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	sig := SignSlack(testSecret, []byte(testBody), ts)

	expired := VerifySlack(testSecret, []byte(testBody), sig, "1700000000", ts.Add(10*time.Minute), DefaultTolerance)
	if expired.Valid {
		t.Fatal("expired slack timestamp should fail")
	}

	tampered := VerifySlack(testSecret, []byte("nope"), sig, "1700000000", ts, DefaultTolerance)
	if tampered.Valid {
		t.Fatal("tampered slack body should fail")
	}

	badTS := VerifySlack(testSecret, []byte(testBody), sig, "nope", ts, DefaultTolerance)
	if badTS.Valid {
		t.Fatal("invalid timestamp should fail")
	}

	missing := VerifySlack(testSecret, []byte(testBody), sig, "", ts, DefaultTolerance)
	if missing.Valid {
		t.Fatal("missing timestamp should fail")
	}

	badVer := VerifySlack(testSecret, []byte(testBody), "v1=abcd", "1700000000", ts, DefaultTolerance)
	if badVer.Valid {
		t.Fatal("unsupported version should fail")
	}
}

func TestGenericSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	combos := []struct {
		algo Algorithm
		enc  Encoding
	}{
		{AlgoSHA256, EncodingHex},
		{AlgoSHA1, EncodingHex},
		{AlgoSHA512, EncodingHex},
		{AlgoSHA256, EncodingBase64},
	}
	for _, tc := range combos {
		t.Run(fmt.Sprintf("%s/%s", tc.algo, tc.enc), func(t *testing.T) {
			sig, err := SignGeneric(testSecret, []byte(testBody), tc.algo, tc.enc)
			if err != nil {
				t.Fatal(err)
			}
			got := VerifyGeneric(testSecret, []byte(testBody), sig, tc.algo, tc.enc)
			if !got.Valid {
				t.Fatalf("expected valid, got %+v", got)
			}
			prefixed := VerifyGeneric(testSecret, []byte(testBody), string(tc.algo)+"="+sig, tc.algo, tc.enc)
			if !prefixed.Valid {
				t.Fatalf("prefixed digest should verify, got %+v", prefixed)
			}
		})
	}
}

func TestGenericRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	sig, err := SignGeneric(testSecret, []byte(testBody), AlgoSHA256, EncodingHex)
	if err != nil {
		t.Fatal(err)
	}
	got := VerifyGeneric("other", []byte(testBody), sig, AlgoSHA256, EncodingHex)
	if got.Valid {
		t.Fatal("wrong secret should fail")
	}
}

func TestSignVerifyOptionsAndMissingSecret(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	for _, p := range []Provider{ProviderGitHub, ProviderStripe, ProviderSlack, ProviderGeneric} {
		sig, err := Sign(Options{Provider: p, Secret: testSecret, Body: []byte(testBody), Timestamp: ts})
		if err != nil {
			t.Fatalf("Sign(%s): %v", p, err)
		}
		got := Verify(Options{Provider: p, Secret: testSecret, Body: []byte(testBody), Timestamp: ts, Now: func() time.Time { return ts }}, sig)
		if !got.Valid {
			t.Fatalf("Verify(%s) failed: %+v", p, got)
		}
	}

	if _, err := Sign(Options{Provider: ProviderGitHub, Body: []byte(testBody)}); err == nil {
		t.Fatal("Sign without secret should fail")
	}
	if got := Verify(Options{Provider: ProviderGitHub, Body: []byte(testBody)}, "sha256=ab"); got.Valid || !strings.Contains(got.Reason, "secret") {
		t.Fatalf("Verify without secret: %+v", got)
	}
	if _, err := Sign(Options{Provider: ProviderAuto, Secret: testSecret, Body: []byte(testBody)}); err == nil {
		t.Fatal("Sign with auto should fail")
	}
	if got := Verify(Options{Provider: ProviderGitHub, Secret: testSecret, Body: []byte(testBody)}, ""); got.Valid {
		t.Fatal("empty signature should fail")
	}
}

func TestDetectAndVerifyRequest(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()
	body := []byte(testBody)

	githubSig, err := SignGitHub(testSecret, body, AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	gh := http.Header{}
	gh.Set("X-Hub-Signature-256", githubSig)
	if p, ok := DetectProvider(gh); !ok || p != ProviderGitHub {
		t.Fatalf("detect github: %q %v", p, ok)
	}
	if got := VerifyRequest(Options{Provider: ProviderAuto, Secret: testSecret, Body: body}, gh); !got.Valid || got.Provider != ProviderGitHub {
		t.Fatalf("VerifyRequest github: %+v", got)
	}

	st := http.Header{}
	st.Set("Stripe-Signature", SignStripe(testSecret, body, ts))
	if p, ok := DetectProvider(st); !ok || p != ProviderStripe {
		t.Fatalf("detect stripe: %q %v", p, ok)
	}
	if got := VerifyRequest(Options{Provider: ProviderAuto, Secret: testSecret, Body: body, Now: func() time.Time { return ts }}, st); !got.Valid || got.Provider != ProviderStripe {
		t.Fatalf("VerifyRequest stripe: %+v", got)
	}

	sl := http.Header{}
	_ = ApplySignatureHeaders(sl, ProviderSlack, SignSlack(testSecret, body, ts), ts)
	if p, ok := DetectProvider(sl); !ok || p != ProviderSlack {
		t.Fatalf("detect slack: %q %v", p, ok)
	}
	if got := VerifyRequest(Options{Provider: ProviderAuto, Secret: testSecret, Body: body, Now: func() time.Time { return ts }}, sl); !got.Valid {
		t.Fatalf("VerifyRequest slack: %+v", got)
	}

	empty := http.Header{}
	if _, ok := DetectProvider(empty); ok {
		t.Fatal("empty headers should not detect a provider")
	}
	if got := VerifyRequest(Options{Provider: ProviderAuto, Secret: testSecret, Body: body}, empty); got.Valid {
		t.Fatal("auto verify with no headers should fail")
	}
	if got := VerifyRequest(Options{Provider: ProviderGeneric, Secret: testSecret, Body: body}, empty); got.Valid {
		t.Fatal("generic VerifyRequest should require an explicit signature")
	}
}

func TestApplySignatureHeaders(t *testing.T) {
	t.Parallel()
	ts := time.Unix(1_700_000_000, 0).UTC()

	h := http.Header{}
	if err := ApplySignatureHeaders(h, ProviderGitHub, "sha256=abc", ts); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Hub-Signature-256") != "sha256=abc" {
		t.Fatalf("github sha256 header: %v", h)
	}

	h = http.Header{}
	if err := ApplySignatureHeaders(h, ProviderGitHub, "sha1=abc", ts); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Hub-Signature") != "sha1=abc" {
		t.Fatalf("github sha1 header: %v", h)
	}

	h = http.Header{}
	if err := ApplySignatureHeaders(h, ProviderGeneric, "deadbeef", ts); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Signature") != "deadbeef" {
		t.Fatalf("generic header: %v", h)
	}

	if err := ApplySignatureHeaders(http.Header{}, Provider("nope"), "x", ts); err == nil {
		t.Fatal("unknown provider should fail")
	}
}

func TestGitHubKnownVector(t *testing.T) {
	t.Parallel()
	// Independently computed HMAC-SHA256 to lock the encoding.
	body := []byte("hello world")
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	got, err := SignGitHub("secret", body, AlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("SignGitHub=%q, want %q", got, want)
	}
}

func TestUnsupportedAlgorithmAndEncoding(t *testing.T) {
	t.Parallel()
	if _, err := SignGeneric(testSecret, []byte(testBody), "md5", EncodingHex); err == nil {
		t.Fatal("md5 should be rejected")
	}
	if _, err := SignGeneric(testSecret, []byte(testBody), AlgoSHA256, "ascii"); err == nil {
		t.Fatal("ascii encoding should be rejected")
	}
	if _, err := SignGitHub(testSecret, []byte(testBody), AlgoSHA512); err == nil {
		t.Fatal("github should reject sha512")
	}
}
