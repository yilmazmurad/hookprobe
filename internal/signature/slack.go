package signature

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignSlack returns a Slack X-Slack-Signature value: v0=<hex>.
// The matching timestamp belongs in X-Slack-Request-Timestamp.
func SignSlack(secret string, body []byte, ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	sum, err := hmacSum(secret, slackSignedPayload(ts.Unix(), body), AlgoSHA256, EncodingHex)
	if err != nil {
		panic(err)
	}
	return "v0=" + sum
}

// VerifySlack checks X-Slack-Signature together with X-Slack-Request-Timestamp.
// A negative tolerance skips the timestamp window check.
func VerifySlack(secret string, body []byte, sigHeader, tsHeader string, now time.Time, tolerance time.Duration) Result {
	result := Result{Provider: ProviderSlack, Signature: sigHeader, Algorithm: AlgoSHA256}
	ts, err := parseSlackTimestamp(tsHeader)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	result.Timestamp = time.Unix(ts, 0).UTC()
	if err := checkTolerance(ts, now, tolerance); err != nil {
		result.Reason = err.Error()
		return result
	}
	got, err := parseSlackSignature(sigHeader)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	want, err := hmacSum(secret, slackSignedPayload(ts, body), AlgoSHA256, EncodingHex)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	if !compareDigest(got, want) {
		result.Reason = "signature mismatch"
		return result
	}
	result.Valid = true
	return result
}

func slackSignedPayload(ts int64, body []byte) []byte {
	prefix := "v0:" + strconv.FormatInt(ts, 10) + ":"
	out := make([]byte, 0, len(prefix)+len(body))
	out = append(out, prefix...)
	out = append(out, body...)
	return out
}

func parseSlackTimestamp(header string) (int64, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, fmt.Errorf("missing X-Slack-Request-Timestamp header")
	}
	ts, err := strconv.ParseInt(header, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid slack timestamp %q", header)
	}
	return ts, nil
}

func parseSlackSignature(header string) (string, error) {
	header = strings.TrimSpace(header)
	version, sum, ok := strings.Cut(header, "=")
	if !ok || sum == "" {
		return "", fmt.Errorf("invalid slack signature header, want v0=<hex>")
	}
	if version != "v0" {
		return "", fmt.Errorf("unsupported slack signature version %q", version)
	}
	return sum, nil
}
