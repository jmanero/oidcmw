package oidcmw

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Errors
var (
	ErrUnsupportedAlgorithm = errors.New("Unsupported signature algorithm")
	ErrUnknownKey           = errors.New("Unknown Key ID")
	ErrInvalidClaim         = errors.New("Invalid token claim")
)

// Header unmarshals common JWT header fields
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// RawToken parses a compact JWT for validation and claim decoding
type RawToken struct {
	Protected []byte

	Header
	Payload   []byte
	Signature []byte
}

// Claims unmarshals common JWT claims
type Claims struct {
	Issuer    string    `json:"iss,omitempty"`
	Subject   string    `json:"sub,omitempty"`
	Audience  string    `json:"aud,omitempty"`
	Expires   time.Time `json:"exp,omitempty"`
	NotBefore time.Time `json:"nbf,omitempty"`
	IssuedAt  time.Time `json:"iat,omitempty"`
	TokenID   string    `json:"jti,omitempty"`
}

type claimwrapper struct {
	*Claims

	// Grab raw byte-strings
	Expires   json.RawMessage `json:"exp,omitempty"`
	NotBefore json.RawMessage `json:"nbf,omitempty"`
	IssuedAt  json.RawMessage `json:"iat,omitempty"`
}

func parsetime(data []byte) (_ time.Time, err error) {
	// Convert second and sub-second values as independent int64. Data contains decimal-
	// character representation of a floating-point; e.g. 123.456
	parts := bytes.SplitN(data, []byte{'.'}, 2)

	// Parse whole seconds
	secs, err := strconv.ParseInt(string(parts[0]), 10, 64)
	if err != nil {
		return
	}

	var nanos int64

	if len(parts) == 2 {
		if length := len(parts[1]); length > 9 {
			// Trim to nanosecond precision
			parts[1] = parts[1][:9]
		} else {
			for length < 9 {
				// Right-pad sub-seconds to nanosecond precision before parsing
				parts[1] = append(parts[1], '0')
			}
		}

		nanos, err = strconv.ParseInt(string(parts[0]), 10, 64)
		if err != nil {
			return
		}
	}

	return time.Unix(secs, nanos), nil
}

// UnmarshalClaims attempts to parse standard claims from a JWT payload
func UnmarshalClaims(data []byte, claims *Claims) (err error) {
	wrapper := claimwrapper{Claims: claims}
	err = json.Unmarshal(data, &wrapper)
	if err != nil {
		return
	}

	claims.Expires, err = parsetime(wrapper.Expires)
	if err != nil {
		return
	}

	claims.NotBefore, err = parsetime(wrapper.NotBefore)
	if err != nil {
		return
	}

	claims.IssuedAt, err = parsetime(wrapper.IssuedAt)
	return
}

// ParseToken decodes a JWT header, payloadm and signature for validation and claim extraction
func ParseToken(data string) (raw RawToken, err error) {
	parts := strings.Split(data, ".")
	if l := len(parts); l != 3 {
		// Only support single header, payload, and signature
		return raw, fmt.Errorf("Unsupported token format: Expected 3 fields, parsed %d", l)
	}

	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}

	// Parse the header segment
	err = json.Unmarshal(head, &raw.Header)
	if err != nil {
		return
	}

	// Put the protected segment of the compact token back together
	raw.Protected = []byte(parts[0] + "." + parts[1])

	// Decode payload and signature segments
	raw.Payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	raw.Signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	return
}
