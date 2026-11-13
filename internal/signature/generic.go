package signature

import (
	"strings"
)

// SignGeneric returns a raw HMAC digest (hex or base64) of the body.
func SignGeneric(secret string, body []byte, algo Algorithm, enc Encoding) (string, error) {
	if algo == "" {
		algo = AlgoSHA256
	}
	if enc == "" {
		enc = EncodingHex
	}
	return hmacSum(secret, body, algo, enc)
}

// VerifyGeneric compares a raw or optionally prefixed HMAC digest.
// Prefixes such as "sha256=" are stripped when present.
func VerifyGeneric(secret string, body []byte, signature string, algo Algorithm, enc Encoding) Result {
	if algo == "" {
		algo = AlgoSHA256
	}
	if enc == "" {
		enc = EncodingHex
	}
	result := Result{Provider: ProviderGeneric, Signature: signature, Algorithm: algo}
	got := strings.TrimSpace(signature)
	if prefix, rest, ok := strings.Cut(got, "="); ok && isAlgorithm(prefix) {
		got = rest
		result.Algorithm = Algorithm(strings.ToLower(prefix))
		algo = result.Algorithm
	}
	if got == "" {
		result.Reason = "missing signature"
		return result
	}
	want, err := hmacSum(secret, body, algo, enc)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	if enc == EncodingHex {
		got = strings.ToLower(got)
		want = strings.ToLower(want)
	}
	if !compareDigest(got, want) {
		result.Reason = "signature mismatch"
		return result
	}
	result.Valid = true
	return result
}

func isAlgorithm(name string) bool {
	switch Algorithm(strings.ToLower(name)) {
	case AlgoSHA1, AlgoSHA256, AlgoSHA512:
		return true
	default:
		return false
	}
}
