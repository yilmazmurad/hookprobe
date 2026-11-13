package signature

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignStripe returns a Stripe-Signature header value: t=<unix>,v1=<hex>.
func SignStripe(secret string, body []byte, ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	t := ts.Unix()
	sum, err := hmacSum(secret, stripeSignedPayload(t, body), AlgoSHA256, EncodingHex)
	if err != nil {
		// hmacSum only fails on unsupported algo/encoding, which are fixed here.
		panic(err)
	}
	return fmt.Sprintf("t=%d,v1=%s", t, sum)
}

// VerifyStripe checks a Stripe-Signature header. Multiple v1 values (secret
// rotation) are accepted if any one matches. A negative tolerance skips the
// timestamp window check.
func VerifyStripe(secret string, body []byte, header string, now time.Time, tolerance time.Duration) Result {
	result := Result{Provider: ProviderStripe, Signature: header, Algorithm: AlgoSHA256}
	ts, versions, err := parseStripeHeader(header)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	result.Timestamp = time.Unix(ts, 0).UTC()
	if err := checkTolerance(ts, now, tolerance); err != nil {
		result.Reason = err.Error()
		return result
	}
	want, err := hmacSum(secret, stripeSignedPayload(ts, body), AlgoSHA256, EncodingHex)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	for _, got := range versions {
		if compareDigest(got, want) {
			result.Valid = true
			return result
		}
	}
	result.Reason = "signature mismatch"
	return result
}

func stripeSignedPayload(ts int64, body []byte) []byte {
	prefix := strconv.FormatInt(ts, 10) + "."
	out := make([]byte, 0, len(prefix)+len(body))
	out = append(out, prefix...)
	out = append(out, body...)
	return out
}

func parseStripeHeader(header string) (int64, []string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, nil, fmt.Errorf("missing Stripe-Signature header")
	}
	var ts int64
	var haveTS bool
	var versions []string
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("invalid stripe timestamp %q", val)
			}
			ts = n
			haveTS = true
		case "v1":
			if val != "" {
				versions = append(versions, val)
			}
		}
	}
	if !haveTS {
		return 0, nil, fmt.Errorf("stripe signature missing t= timestamp")
	}
	if len(versions) == 0 {
		return 0, nil, fmt.Errorf("stripe signature missing v1= digest")
	}
	return ts, versions, nil
}

func checkTolerance(ts int64, now time.Time, tolerance time.Duration) error {
	if tolerance < 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	delta := now.Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > tolerance {
		return fmt.Errorf("timestamp %d is outside the %s tolerance window", ts, tolerance)
	}
	return nil
}
