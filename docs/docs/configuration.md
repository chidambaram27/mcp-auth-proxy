---
sidebar_position: 7
---

# Configuration Reference

Complete reference for all MCP Auth Proxy configuration options.

## Command Line Options

### Required Options

| Option           | Environment Variable | Default            | Description                |
| ---------------- | -------------------- | ------------------ | -------------------------- |
| `--external-url` | `EXTERNAL_URL`       | `http://localhost` | External URL for the proxy |

### TLS Options

| Option                | Environment Variable | Default                                          | Description                                                                                        |
| --------------------- | -------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `--no-auto-tls`       | `NO_AUTO_TLS`        | `false`                                          | Disable automatic TLS host detection from externalURL (ignored when `--tls-cert-file` is provided) |
| `--tls-accept-tos`    | `TLS_ACCEPT_TOS`     | `false`                                          | Accept TLS terms of service                                                                        |
| `--tls-directory-url` | `TLS_DIRECTORY_URL`  | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL for TLS certificates                                                            |
| `--tls-host`          | `TLS_HOST`           | -                                                | Host name used for automatic TLS certificate provisioning                                          |
| `--tls-cert-file`     | `TLS_CERT_FILE`      | -                                                | Path to PEM-encoded TLS certificate served directly by the proxy (auto-reloads on file changes)    |
| `--tls-key-file`      | `TLS_KEY_FILE`       | -                                                | Path to PEM-encoded TLS private key (requires `--tls-cert-file`, auto-reloads on file changes)     |

### Authentication Options

#### Password Authentication

| Option                      | Environment Variable      | Default | Description                                                                                  |
| --------------------------- | ------------------------- | ------- | -------------------------------------------------------------------------------------------- |
| `--no-provider-auto-select` | `NO_PROVIDER_AUTO_SELECT` | `false` | Disable auto-redirect when only one OAuth/OIDC provider is configured and no password is set |
| `--password`                | `PASSWORD`                | -       | Plain text password for authentication (will be hashed with bcrypt)                          |
| `--password-hash`           | `PASSWORD_HASH`           | -       | Bcrypt hash of password for authentication                                                   |

#### Google OAuth

| Option                        | Environment Variable        | Default | Description                                           |
| ----------------------------- | --------------------------- | ------- | ----------------------------------------------------- |
| `--google-client-id`          | `GOOGLE_CLIENT_ID`          | -       | Google OAuth client ID                                |
| `--google-client-secret`      | `GOOGLE_CLIENT_SECRET`      | -       | Google OAuth client secret                            |
| `--google-allowed-users`      | `GOOGLE_ALLOWED_USERS`      | -       | Comma-separated list of allowed Google users (emails) |
| `--google-allowed-workspaces` | `GOOGLE_ALLOWED_WORKSPACES` | -       | Comma-separated list of allowed Google workspaces     |

#### GitHub OAuth

| Option                   | Environment Variable   | Default | Description                                                                                                                      |
| ------------------------ | ---------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `--github-url`           | `GITHUB_URL`           | -       | GitHub custom instance URL                                                                                                       |
| `--github-api-url`       | `GITHUB_API_URL`       | -       | GitHub custom API URL                                                                                                            |
| `--github-client-id`     | `GITHUB_CLIENT_ID`     | -       | GitHub OAuth client ID                                                                                                           |
| `--github-client-secret` | `GITHUB_CLIENT_SECRET` | -       | GitHub OAuth client secret                                                                                                       |
| `--github-allowed-users` | `GITHUB_ALLOWED_USERS` | -       | Comma-separated list of allowed GitHub users (usernames)                                                                         |
| `--github-allowed-orgs`  | `GITHUB_ALLOWED_ORGS`  | -       | Comma-separated list of allowed GitHub organizations. You can also restrict access to specific teams using the format `Org:Team` |

If using GitHub Enterprise Server or Cloud, set `--github-url` to the instance URL (eg `https://github.example.com`) and `--github-api-url` to the base of the instance's API URL (eg `https://github.example.com/api/v3`).

#### Generic OIDC

| Option                           | Environment Variable           | Default                | Description                                                                       |
| -------------------------------- | ------------------------------ | ---------------------- | --------------------------------------------------------------------------------- |
| `--oidc-configuration-url`       | `OIDC_CONFIGURATION_URL`       | -                      | OIDC configuration URL                                                            |
| `--oidc-client-id`               | `OIDC_CLIENT_ID`               | -                      | OIDC client ID                                                                    |
| `--oidc-client-secret`           | `OIDC_CLIENT_SECRET`           | -                      | OIDC client secret                                                                |
| `--oidc-allowed-users`           | `OIDC_ALLOWED_USERS`           | -                      | Comma-separated list of allowed OIDC users (exact match)                          |
| `--oidc-allowed-users-glob`      | `OIDC_ALLOWED_USERS_GLOB`      | -                      | Comma-separated list of glob patterns for allowed OIDC users                      |
| `--oidc-allowed-attributes`      | `OIDC_ALLOWED_ATTRIBUTES`      | -                      | Comma-separated list of allowed attribute key=value pairs (e.g., `/groups=admin`) |
| `--oidc-allowed-attributes-glob` | `OIDC_ALLOWED_ATTRIBUTES_GLOB` | -                      | Comma-separated list of attribute key=pattern pairs for glob matching             |
| `--oidc-provider-name`           | `OIDC_PROVIDER_NAME`           | `OIDC`                 | Display name for OIDC provider                                                    |
| `--oidc-scopes`                  | `OIDC_SCOPES`                  | `openid,profile,email` | Comma-separated list of OIDC scopes                                               |
| `--oidc-user-id-field`           | `OIDC_USER_ID_FIELD`           | `/email`               | JSON pointer to user ID field in userinfo endpoint response                       |

##### OIDC User Matching

You can use both exact matching and glob patterns for OIDC user authorization:

- **Exact matching** (`--oidc-allowed-users`): Users must match exactly
- **Glob patterns** (`--oidc-allowed-users-glob`): Users are matched against [glob patterns](https://github.com/gobwas/glob)

**Examples:**

```bash
# Exact matching
--oidc-allowed-users "user1@example.com,admin@company.org"

# Glob patterns - allow all users from example.com
--oidc-allowed-users-glob "*@example.com"

# Combined exact and glob matching
--oidc-allowed-users "specific@user.com" \
--oidc-allowed-users-glob "*@example.com"
```

##### OIDC Attribute-Based Authorization

You can also authorize users based on attributes from the userinfo endpoint (e.g., group memberships, roles, departments). This is useful when you need to restrict access based on IdP-provided claims beyond just the user ID.

- **Exact attribute matching** (`--oidc-allowed-attributes`): Attribute values must match exactly
- **Glob attribute patterns** (`--oidc-allowed-attributes-glob`): Attribute values are matched against glob patterns

Attribute keys use [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) syntax to reference fields in the userinfo response. Both string and array attribute values are supported.

**Examples:**

```bash
# Allow users in the "engineering" department
--oidc-allowed-attributes "/department=engineering"

# Allow users in the "admin" group (works with array values)
--oidc-allowed-attributes "/groups=admin"

# Allow users whose group matches a pattern
--oidc-allowed-attributes-glob "/groups=*-admins"

# Nested attribute (e.g., {"org": {"team": "platform"}})
--oidc-allowed-attributes "/org/team=platform"

# Multiple allowed values for the same attribute
--oidc-allowed-attributes "/groups=admin,/groups=developers"

# Combined with user matching
--oidc-allowed-users "admin@example.com" \
--oidc-allowed-attributes "/groups=data-science" \
--oidc-allowed-attributes-glob "/groups=*-admins"
```

:::tip Okta Configuration
For Okta, you typically need to:

1. Add the `groups` scope: `--oidc-scopes "openid,profile,email,groups"`
2. Configure a groups claim in Okta Admin (Security → API → Authorization Servers → Claims)
   :::

### Cryptographic Key Options

- **`AUTH_HMAC_SECRET`** — Base64-encoded 32-byte secret for HMAC/cookie signing. Default: auto-generated.
- **`JWT_PRIVATE_KEY`** — PEM-encoded RSA private key (PKCS8) for JWT signing. Default: auto-generated.

When set, these environment variables take precedence over the file-based keys in `{data-path}/secret` and `{data-path}/private_key.pem`. This is useful for deployments without persistent volumes (e.g., Kubernetes) where pod restarts would otherwise regenerate keys and invalidate all existing OAuth tokens.

To generate suitable values:

```bash
# Generate AUTH_HMAC_SECRET (base64-encoded 32 random bytes)
openssl rand -base64 32

# Generate JWT_PRIVATE_KEY (RSA 2048-bit PKCS8 PEM)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
```

### Consent Page Branding Options

These options customize the consent (authorize) page that users see when an MCP client asks for access. All are optional; when unset, the page shows the external host, a built-in icon and the default texts.

| Option                    | Environment Variable    | Default | Description                                                                                                                                |
| ------------------------- | ----------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `--authorize-server-name` | `AUTHORIZE_SERVER_NAME` | -       | Friendly name shown instead of the external host (e.g. `Trino (staging)`). Plain text, HTML-escaped                                        |
| `--authorize-logo`        | `AUTHORIZE_LOGO`        | -       | Logo: a file path (PNG/JPG/SVG/GIF/WebP, max 512 KiB, inlined as a `data:` URI at startup) or an `http(s)` URL. `-` hides the default icon |
| `--authorize-banner`      | `AUTHORIZE_BANNER`      | -       | HTML banner shown above the request details. `-` hides the default message                                                                 |
| `--authorize-footer`      | `AUTHORIZE_FOOTER`      | -       | HTML footer shown at the bottom of the page. `-` hides the default footer                                                                  |

`AUTHORIZE_BANNER` and `AUTHORIZE_FOOTER` are rendered as trusted HTML (operator-controlled). The page sends a strict Content Security Policy (`default-src 'none'`, no scripts, `frame-ancestors 'none'`): `img-src` is `'none'` unless a logo is configured (then `data:` for a file logo or the logo URL's origin), and `form-action` allows `'self'` plus the origin of the client's (already validated) redirect URI. The client name registered via dynamic client registration is shown HTML-escaped, with control and invisible formatting characters (e.g. bidi overrides) removed.

An unusable `--authorize-logo` (missing, oversized or unsupported file, or a non-`http(s)` URL such as `javascript:`) does not stop the proxy: it logs an error at startup and shows the default icon. An `http://` logo URL logs a warning, because browsers block it as mixed content on an `https` consent page.

```bash title="Example"
--authorize-server-name "Trino (staging)" \
--authorize-logo "https://example.com/logo.png" \
--authorize-banner "<strong>Example MCP</strong> &mdash; authorize access to <strong>Trino (staging)</strong>." \
--authorize-footer "Questions? Reach out in <strong>#support</strong>."
```

### Token Lifespan Options

Lifetimes of the tokens issued by the built-in authorization server to MCP clients. Values are Go durations (`90s`, `15m`, `1h`, `720h`; no `d` unit) and must be positive (`MAX_SESSION_AGE` may be `0`).

| Option                         | Environment Variable         | Default          | Description                                                |
| ------------------------------ | ---------------------------- | ---------------- | ---------------------------------------------------------- |
| `--access-token-lifespan`      | `ACCESS_TOKEN_LIFESPAN`      | `24h`            | Lifetime of access tokens (JWT `exp`, `expires_in`)        |
| `--refresh-token-lifespan`     | `REFRESH_TOKEN_LIFESPAN`     | `720h` (30 days) | Lifetime of refresh tokens                                 |
| `--authorize-code-lifespan`    | `AUTHORIZE_CODE_LIFESPAN`    | `15m`            | Lifetime of authorization codes (consent → token exchange) |
| `--max-session-age`            | `MAX_SESSION_AGE`            | `0` (off)        | Maximum session length from the user's login, see below    |
| `--refresh-token-grace-period` | `REFRESH_TOKEN_GRACE_PERIOD` | `0s`             | How long a used refresh token is still accepted, see below |

Access tokens are self-contained JWTs and are accepted until they expire, so `ACCESS_TOKEN_LIFESPAN` bounds how long a user keeps access after being removed at the identity provider. Every refresh issues a new refresh token with a fresh `REFRESH_TOKEN_LIFESPAN`, so the refresh token lifespan limits idle time, not the total session length.

`MAX_SESSION_AGE` adds an absolute cap: it is counted from the user's login at the identity provider (the `auth_time` claim) and does not move on refresh. Tokens issued near the end of the session expire when the session ends, and once it has ended the token endpoint answers `invalid_grant`, so the MCP client has to send the user through the login (and the identity provider's group/user checks) again. With the default `0` there is no cap.

Refresh tokens are single use. Each refresh returns a new refresh token, and the old one stops working. If an already used refresh token is presented again (for example a leaked token replayed by someone else), the request fails with `invalid_grant` and **all refresh tokens of that authorization are revoked**, so the legitimate client has to sign in again too (OAuth 2.0 Security BCP, refresh token rotation). `REFRESH_TOKEN_GRACE_PERIOD` (e.g. `30s`) lets a client retry with the old token for a short time after it was first used, e.g. when the refresh response was lost on the network. It is counted from the first use and doesn't change the reuse handling after it. Access tokens that were already issued stay valid until they expire, because the proxy checks them without a database lookup.

Access tokens carry `iat` / `nbf` = the time they were issued (also for refreshed tokens), `exp` = `iat` + `ACCESS_TOKEN_LIFESPAN`, and `auth_time` = the login time.

```bash title="Example"
--access-token-lifespan 1h \
--refresh-token-lifespan 168h \
--authorize-code-lifespan 5m \
--max-session-age 168h
```

### Server Options

| Option         | Environment Variable | Default  | Description                  |
| -------------- | -------------------- | -------- | ---------------------------- |
| `--listen`     | `LISTEN`             | `:80`    | Address to listen on         |
| `--tls-listen` | `TLS_LISTEN`         | `:443`   | Address to listen on for TLS |
| `--data-path`  | `DATA_PATH`          | `./data` | Path to the data directory   |

### Repository Options

| Option                 | Environment Variable | Default | Description                                                                                                           |
| ---------------------- | -------------------- | ------- | --------------------------------------------------------------------------------------------------------------------- |
| `--repository-backend` | `REPOSITORY_BACKEND` | `local` | Storage backend for OAuth state. Supported values: `local` (embedded BoltDB), `sqlite`, `postgres`, or `mysql`.       |
| `--repository-dsn`     | `REPOSITORY_DSN`     | -       | Connection string passed directly to the SQL driver. Required when `--repository-backend` is `sqlite/postgres/mysql`. |

`local` uses an embedded BoltDB file under `--data-path`. SQL backends run migrations automatically via GORM; the DSN must be valid for the chosen driver (examples below). The deprecated value `sql` is no longer accepted—select the concrete driver instead.

```bash title="DSN examples"
# sqlite
--repository-backend sqlite --repository-dsn "file:data/mcp-auth.db?cache=shared&mode=rwc"

# postgres
--repository-backend postgres --repository-dsn "postgres://user:pass@hostname:5432/database?sslmode=disable"

# mysql
--repository-backend mysql --repository-dsn "user:pass@tcp(hostname:3306)/database?parseTime=true"
```

### Proxy Options

| Option                          | Environment Variable          | Default     | Description                                                                                           |
| ------------------------------- | ----------------------------- | ----------- | ----------------------------------------------------------------------------------------------------- |
| `--proxy-bearer-token`          | `PROXY_BEARER_TOKEN`          | -           | Bearer token to add to Authorization header when proxying requests                                    |
| `--proxy-forward-authorization` | `PROXY_FORWARD_AUTHORIZATION` | `false`     | Forward the incoming Authorization bearer token to the backend after validation                       |
| `--proxy-headers`               | `PROXY_HEADERS`               | -           | Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2) |
| `--header-mapping`              | `HEADER_MAPPING`              | -           | Comma-separated mapping of JSON pointer paths to header names (e.g., `/email:X-Forwarded-Email`)      |
| `--header-mapping-base`         | `HEADER_MAPPING_BASE`         | `/userinfo` | JSON pointer base path for header mapping claims lookup (e.g., `/userinfo` or `/`)                    |
| `--http-streaming-only`         | `HTTP_STREAMING_ONLY`         | `false`     | Reject SSE (GET) requests and keep the backend operating in HTTP streaming-only mode                  |
| `--trusted-proxies`             | `TRUSTED_PROXIES`             | -           | Comma-separated list of trusted proxies (IP addresses or CIDR ranges)                                 |

For practical configuration examples including environment variables, Docker Compose, and Kubernetes deployments, see the [Configuration Examples](./examples.md) page.
