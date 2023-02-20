package oidcmw

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"go.uber.org/multierr"
)

// Errors
var (
	ErrInvalidLength      = errors.New("Invalid data length for type")
	ErrUnsupportedKeyType = errors.New("Unsupported JWK key-type")
)

// KeySource returns a PublicKey for a key identifier
type KeySource interface {
	GetKey(string) (crypto.PublicKey, bool)
	RefreshKeys(context.Context) error
}

// KeyCache fetches PublicKeys from a JSON Web Keyset service endpoint
type KeyCache struct {
	Endpoint string

	keys map[string]crypto.PublicKey
	mu   sync.RWMutex
}

// JWK unmarshals RSA or EC-type JSON Web Key public parameters
type JWK struct {
	Algorithm string `json:"alg"`
	Type      string `json:"kty"`
	Use       string `json:"use"`
	ID        string `json:"kid"`

	// x509 Properties
	X509Thumbprint string   `json:"x5t"`
	X509Chain      []string `json:"x5c"`

	// RSA Key
	E string `json:"e"`
	N string `json:"n"`

	// EC Key
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

// DecodeBigInt parses a base-64 string into a BitInt
func DecodeBigInt(str string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(data), nil
}

// DecodeInt unpacks big-endian bytes from a base64 string into a 32-bit integer
func DecodeInt(str string) (value int, err error) {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return
	}

	length := len(data)
	if length > 4 {
		return 0, fmt.Errorf("%w: Can not decode `%s` (len %d) into an int", ErrInvalidLength, str, length)
	}

	length--

	for i, v := range data {
		value += int(v) << (8 * (length - i))
	}

	return
}

// PublicKey attempts to construct a crypto.PublicKey instance from decoded parameters
func (key *JWK) PublicKey() (crypto.PublicKey, error) {
	switch strings.ToLower(key.Type) {
	case "rsa":
		n, err := DecodeBigInt(key.N)
		if err != nil {
			return nil, err
		}

		e, err := DecodeInt(key.E)
		if err != nil {
			return nil, err
		}

		return &rsa.PublicKey{N: n, E: e}, nil
	default:
		// FIXME: Add EC support
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyType, key.Type)
	}
}

// KeySet unmarshals a JSON Web Keyset payload
type KeySet struct {
	Keys []JWK `json:"keys"`
}

// RefreshKeys attempts to fetch keys from a JSON Web Keyset API endpoint
func (cache *KeyCache) RefreshKeys(ctx context.Context) (err error) {
	fmt.Println("Fetching keys from", cache.Endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cache.Endpoint, http.NoBody)
	if err != nil {
		return
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	// Limit to 1 MB to avoid pathological attacks
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected response from service\n\t%d %s\n\t%s", res.StatusCode, res.Status, string(data))
	}

	var message KeySet
	err = json.Unmarshal(data, &message)
	if err != nil {
		return
	}

	keys := make(map[string]crypto.PublicKey)
	for _, entry := range message.Keys {
		key, err1 := entry.PublicKey()
		if err1 != nil {
			err = multierr.Append(err, err1)
			continue
		}

		keys[entry.ID] = key
	}

	// Don't replace the cache if update failed
	if err != nil {
		return
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	fmt.Println("Fetched", len(keys), "keys")
	cache.keys = keys
	return
}

// GetKey attempts to fetch a crypto.PublicKey from the cache
func (cache *KeyCache) GetKey(kid string) (key crypto.PublicKey, has bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	key, has = cache.keys[kid]
	return
}
