package oidcmw

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
)

// Config for middleware plugin
type Config struct {
	// Cookie that Identity Tokens are loaded from
	CookieName string `json:"cookie_name" toml:"cookie_name" yaml:"cookie_name" mapstructure:"cookie_name"`
	// URL to a login page for unauthenticated requests
	LoginURL string `json:"login_url" toml:"login_url" yaml:"login_url" mapstructure:"login_url"`

	// Issuer is used to validate token issuers, and is used to auto-configure OIDC endpoints
	Issuer string `json:"issuer" toml:"issuer" yaml:"issuer" mapstructure:"issuer"`
	// ClientID is used to restrict token audience
	ClientID string `json:"client_id" toml:"client_id" yaml:"client_id" mapstructure:"client_id"`
	// Enable configuration from {{Issuer}}/.well-known/openid-configuration
	AutoConfigure bool `json:"auto_configure" toml:"auto_configure" yaml:"auto_configure" mapstructure:"auto_configure"`

	// Configures or override the endpoint that serves a JSON Web Keyset to validate tokens
	KeysetEndpoint string `json:"jwks_uri" toml:"jwks_uri" yaml:"jwks_uri" mapstructure:"jwks_uri"`
	// AuthorizationEndpoint string
	// TokenEndpoint string

	// Optionally, Limit accepted signing tokens
	SupportedSigningAlgorithms []string `json:"supported_signing_algs" toml:"supported_signing_algs" yaml:"supported_signing_algs" mapstructure:"supported_signing_algs"`

	// Optionally, disable key validation steps
	SkipClientIDCheck bool `json:"skip_clientid_check" toml:"skip_clientid_check" yaml:"skip_clientid_check" mapstructure:"skip_clientid_check"`
	SkipIssuerCheck   bool `json:"skip_issuer_check" toml:"skip_issuer_check" yaml:"skip_issuer_check" mapstructure:"skip_issuer_check"`
	SkipExpiryCheck   bool `json:"skip_expiry_check" toml:"skip_expiry_check" yaml:"skip_expiry_check" mapstructure:"skip_expiry_check"`

	// XXX: DANGER ZONE
	InsecureSkipSignatureCheck bool `json:"insecure_skip_signature_check" toml:"insecure_skip_signature_check" yaml:"insecure_skip_signature_check" mapstructure:"insecure_skip_signature_check"`
}

// CreateConfig instantiates a new Config instance with minimal defaults
func CreateConfig() *Config {
	return &Config{
		SupportedSigningAlgorithms: SupportedSigningAlgorithms,

		CookieName:    "traefik.oidc-session",
		AutoConfigure: true,
	}
}

// WellKnown loads OIDC configuration from a well-known endpoint
type WellKnown struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	KeysetEndpoint        string `json:"jwks_uri"`
}

// AutoConfigure attempts to load well-known configuration from an issuer endpoint
func AutoConfigure(ctx context.Context, issuer string) (info WellKnown, err error) {
	fmt.Println("Fetching well-known configuration from", issuer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer, http.NoBody)
	if err != nil {
		return
	}

	req.URL.Path = path.Join(req.URL.Path, ".well-known/openid-configuration")
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
		return info, fmt.Errorf("Unexpected response from service\n\t%d %s\n\t%s", res.StatusCode, res.Status, string(data))
	}

	err = json.Unmarshal(data, &info)
	return
}
