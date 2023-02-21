OIDC Authentication Middleware
==============================

This module provides a Traefik middleware plugin that validates a JWT Identity Token in a request cookie. If the cookie is not present, or the JWT is not valid, the middleware redirects the user-agent to a login page, which should initiate an oauth2 handshake with an OIDC provider, and set the configured cookie on successful callback and code-exchange.

## Configuration

Minimal dynamic configuration:

```yaml
http:
  middlewares:
    authenticate:
      plugin:
        oidcmw:
          issuer: https://openauth.provider.com/
          client_id: deadbeef01
          login_url: /login
```

Supported configuration parameters:

- cookie_name [`string`, default: "traefik.oidc-session"]: Cookie that Identity Tokens are loaded from
- login_url [`string`, default: "/login"]: URL to a login page for unauthenticated requests
- issuer [`string`, required]: Issuer is used to validate token issuers, and is used to auto-configure OIDC endpoints
- client_id [`string`, required]: ClientID is used to validate the token audience
- auto_configure [`bool`, default: true]: Enable configuration from `{{Issuer}}/.well-known/openid-configuration`
- jwks_uri [`string`]: Configures or override the endpoint that serves a JSON Web Keyset to validate tokens. When `auto_configure` is enabled, this is loaded from a well-known OIDC configurations by default.
- supported_signing_algs [`[]string`]: Limit accepted signing tokens
- skip_clientid_check [`bool`, default: false]: Disable client_id/token audience checking
- skip_issuer_check [`bool`, default: false]: Disable token issuer checking
- skip_expiry_check [`bool`, default: false]: Disable token expiry checking
- insecure_skip_signature_check [bool, default: false]: Disable token signature checking. **You probably don't want to do this**
