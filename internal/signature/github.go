package signature

import (
	"fmt"
	"strings"
)

// SignGitHub returns a GitHub webhook signature in the form "sha256=<hex>"
// or "sha1=<hex>".
func SignGitHub(secret string, body []byte, algo Algorithm) (string, error) {
	if algo == "" {
		algo = AlgoSHA256
	}
	if algo != AlgoSHA256 && algo != AlgoSHA1 {
		return "", fmt.Errorf("github signatures support sha1 or sha256, got %q", algo)
	}
	sum, err := hmacSum(secret, body, algo, EncodingHex)
	if err != nil {
		return "", err
	}
	return string(algo) + "=" + sum, nil
}

// VerifyGitHub checks a GitHub X-Hub-Signature or X-Hub-Signature-256 value.
func VerifyGitHub(secret string, body []byte, header string) Result {
	result := Result{Provider: ProviderGitHub, Signature: header}
	algo, got, err := parsePrefixedHex(header)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	result.Algorithm = algo
	want, err := SignGitHub(secret, body, algo)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	_, wantSum, _ := parsePrefixedHex(want)
	if !compareDigest(got, wantSum) {
		result.Reason = "signature mismatch"
		return result
	}
	result.Valid = true
	return result
}

func parsePrefixedHex(header string) (Algorithm, string, error) {
	header = strings.TrimSpace(header)
	algo, sum, ok := strings.Cut(header, "=")
	if !ok || algo == "" || sum == "" {
		return "", "", fmt.Errorf("invalid github signature header, want sha256=<hex> or sha1=<hex>")
	}
	switch Algorithm(strings.ToLower(algo)) {
	case AlgoSHA1, AlgoSHA256:
		return Algorithm(strings.ToLower(algo)), strings.ToLower(sum), nil
	default:
		return "", "", fmt.Errorf("unsupported github signature algorithm %q", algo)
	}
}
