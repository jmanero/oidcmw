package oidcmw

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"time"

	"golang.org/x/exp/slices"
)

// SupportedSigningAlgorithms is the default set of algorithms supported by the module
var SupportedSigningAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
}

// Verifier configures authentication of JWTs. Heavily borrowed from
// https://github.com/coreos/go-oidc/blob/v3.5.0/oidc/verify.go#L80
type Verifier struct {
	// FIXME Yaegi doesn't handle interfaces correctly... I suspect that it's related to the bug that breaks go-jose https://github.com/traefik/yaegi/issues/1502 -- @jmanero Feb/19/2023
	// KeySource
	*KeyCache

	// Expected audience of the token. For a majority of the cases this is expected to be
	// the ID of the client that initialized the login flow. It may occasionally differ if
	// the provider supports the authorizing party (azp) claim.
	//
	// If not provided, users must explicitly set SkipClientIDCheck.
	ClientID string
	// If true, no ClientID check performed. Must be true if ClientID field is empty.
	SkipClientIDCheck bool

	// Expected Issuer of the token
	Issuer string
	// SkipIssuerCheck is intended for specialized cases where the the caller wishes to
	// defer issuer validation. When enabled, callers MUST independently verify the Token's
	// Issuer is a known good value.
	//
	// Mismatched issuers often indicate client mis-configuration. If mismatches are
	// unexpected, evaluate if the provided issuer URL is incorrect instead of enabling
	// this option.
	SkipIssuerCheck bool

	// If specified, only this set of algorithms may be used to sign the JWT.
	//
	// If the IDTokenVerifier is created from a provider with (*Provider).Verifier, this
	// defaults to the set of algorithms the provider supports. Otherwise this values
	// defaults to RS256.
	SupportedSigningAlgorithms []string

	// Time function to check Token expiry. Defaults to time.Now
	Now func() time.Time
	// If true, token expiry is not checked.
	SkipExpiryCheck bool

	// InsecureSkipSignatureCheck causes this package to skip JWT signature validation.
	// It's intended for special cases where providers (such as Azure), use the "none"
	// algorithm.
	//
	// This option can only be enabled safely when the ID Token is received directly
	// from the provider after the token exchange.
	//
	// This option MUST NOT be used when receiving an ID Token from sources other
	// than the token endpoint.
	InsecureSkipSignatureCheck bool
}

// Verify an issued token
func (verifier *Verifier) Verify(raw RawToken) (claims Claims, err error) {
	// Parse claims. Do simple checks before cryptography
	err = UnmarshalClaims(raw.Payload, &claims)

	if len(verifier.SupportedSigningAlgorithms) > 0 {
		slices.Contains(verifier.SupportedSigningAlgorithms, raw.Algorithm)
	}

	if !verifier.SkipClientIDCheck && claims.Audience != verifier.ClientID {
		return claims, fmt.Errorf("%w: Invalid `aud` claim `%s` (expected `%s`)", ErrInvalidClaim, claims.Audience, verifier.ClientID)
	}

	if !verifier.SkipIssuerCheck && claims.Issuer != verifier.Issuer {
		return claims, fmt.Errorf("%w: Invalid `iss` claim `%s` (expected `%s`)", ErrInvalidClaim, claims.Issuer, verifier.Issuer)
	}

	if !verifier.SkipExpiryCheck {
		now := verifier.Now()

		// Enforce Expires claim
		if claims.Expires.Before(now) {
			return claims, fmt.Errorf("%w: Token expired at %s (now %s)", ErrInvalidClaim, claims.Expires, now)
		}

		// Enforce NotBefore claim if defined
		if !claims.NotBefore.IsZero() {
			// Set to 5 minutes since this is what other OpenID Connect providers do to deal with clock skew.
			// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/6.12.2/src/Microsoft.IdentityModel.Tokens/TokenValidationParameters.cs#L149-L153
			skew := 5 * time.Minute

			if claims.NotBefore.After(now.Add(skew)) {
				return claims, fmt.Errorf("%w: Token is not valid until %s (now %s)", ErrInvalidClaim, claims.NotBefore, now)
			}
		}
	}

	if verifier.InsecureSkipSignatureCheck {
		// XXX: DANGER ZONE
		return
	}

	key, has := verifier.GetKey(raw.KeyID)
	if !has {
		// TODO: Try to refresh the KeySource here.
		return claims, fmt.Errorf("%w: %s", ErrUnknownKey, raw.KeyID)
	}

	switch raw.Algorithm {
	case "RS256":
		err = raw.VerifyPKCS1v15(key, crypto.SHA256)
	case "RS384":
		err = raw.VerifyPKCS1v15(key, crypto.SHA384)
	case "RS512":
		err = raw.VerifyPKCS1v15(key, crypto.SHA512)
	case "PS256":
		err = raw.VerifyPSS(key, crypto.SHA256)
	case "PS384":
		err = raw.VerifyPSS(key, crypto.SHA384)
	case "PS512":
		err = raw.VerifyPSS(key, crypto.SHA512)
	default:
		// TODO: Support ECDSA and HMAC algorithms
		err = fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, raw.Algorithm)
	}

	return
}

// VerifyPKCS1v15 performs PKCS1v1.5 signature verification for a given Hash
func (raw *RawToken) VerifyPKCS1v15(key crypto.PublicKey, hash crypto.Hash) error {
	rkey, is := key.(*rsa.PublicKey)
	if !is {
		return fmt.Errorf("%w: Can not use %T as an rsa.PublicKey", ErrUnsupportedKeyType, key)
	}

	hasher := hash.New()
	_, err := hasher.Write(raw.Protected)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(rkey, hash, hasher.Sum(nil), raw.Signature)
}

// VerifyPSS performs PSS signature verification for a given Hash
func (raw *RawToken) VerifyPSS(key crypto.PublicKey, hash crypto.Hash) error {
	rkey, is := key.(*rsa.PublicKey)
	if !is {
		return fmt.Errorf("%w: Can not use %T as an rsa.PublicKey", ErrUnsupportedKeyType, key)
	}

	hasher := hash.New()
	_, err := hasher.Write(raw.Protected)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(rkey, hash, hasher.Sum(nil), raw.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
}
