package gatewaytool

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
)

type Fingerprinter struct{ key []byte }

func NewFingerprinter(key []byte) (*Fingerprinter, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("tool fingerprint key must contain at least 32 bytes")
	}
	return &Fingerprinter{key: slices.Clone(key)}, nil
}

func (f *Fingerprinter) Fingerprint(value string) string {
	mac := hmac.New(sha256.New, f.key)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}
