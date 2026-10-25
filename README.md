# MCP Auth Proxy

> **This is a fork** of [sigbit/mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy), maintained at
> [chidambaram27/mcp-auth-proxy](https://github.com/chidambaram27/mcp-auth-proxy). See [Fork changes](#fork-changes).

![Secure your MCP server with OAuth 2.1 — in a minute](./mcp-auth-proxy.svg)

> If you found value here, please consider starring.

## Overview

- **Drop-in OAuth 2.1/OIDC gateway for MCP servers — put it in front, no code changes.**
- **Your IdP, your choice**: Google, GitHub, or any OIDC provider — e.g. Okta, Auth0, Azure AD, Keycloak — plus optional password.
- **Flexible user matching**: Support exact matching and glob patterns for user authorization (e.g., `*@company.com`)
- **Publish local MCP servers safely**: Supports all stdio, SSE, and HTTP transports. For stdio, traffic is converted to `/mcp`. For SSE/HTTP, it's proxied as-is. Of course, with authentication.
- **Verified across major MCP clients**: Claude, Claude Code, ChatGPT, GitHub Copilot, Cursor, etc. — the proxy smooths client-specific quirks for consistent auth.

---

📖 **For detailed usage, configuration, and examples, see the [Documentation](https://sigbit.github.io/mcp-auth-proxy/)**

## Quickstart

> Domain binding & 80/443 must be accessible from outside.

Download binary from [release](https://github.com/sigbit/mcp-auth-proxy/releases) page.

If you use stdio transport

```sh
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password changeme \
  -- npx -y @modelcontextprotocol/server-filesystem ./
```

That's it! Your HTTP endpoint is now available at `https://{your-domain}/mcp`.

- stdio (when a command is specified): MCP endpoint is https://{your-domain}/mcp.
- SSE/HTTP (when a URL is specified): MCP endpoint uses the backend’s original path (no conversion).

> Already have certificates? Pass `--tls-cert-file` and `--tls-key-file` instead of `--tls-accept-tos`.

## Why not MCP Gateway?

mcp-auth-proxy: **A lightweight proxy that adds authentication to any MCP server** (optional stdio→HTTP(S) conversion)  
MCP Gateway: **A hub to orchestrate multiple MCP servers** (aggregation, catalog integration)

### When to choose `mcp-auth-proxy`

- **You just need to add auth to one or a few MCPs** (enforce OAuth/OIDC/password-only)
- **Catalog integration and aggregation aren’t needed** (e.g., self-hosted or independently managed MCP deployments)

### When to choose MCP Gateway

- **You need to manage multiple MCPs centrally** (aggregation, policies/permissions, auditing, centralized logging)
- **You want catalog integration and aggregation**

_Note_: They are not mutually exclusive. You can **put `mcp-auth-proxy` in front of a Gateway's public endpoint to enforce authentication** if the Gateway itself doesn't handle it.

**TL;DR:** Orchestrate many → Gateway / Expose safely & quickly → mcp-auth-proxy

## Verified MCP Client

| MCP Client        | Status | Notes                                            |
| ----------------- | ------ | ------------------------------------------------ |
| Claude - Web      | ✅     |                                                  |
| Claude - Desktop  | ✅     |                                                  |
| Claude Code       | ✅     |                                                  |
| ChatGPT - Web     | ✅     | Need to implement `search` and `fetch` tools.(1) |
| ChatGPT - Desktop | ✅     | Need to implement `search` and `fetch` tools.(1) |
| GitHub Copilot    | ✅     |                                                  |
| Cursor            | ✅     |                                                  |

- \*1: https://platform.openai.com/docs/mcp

## Fork changes

This fork tracks upstream `main` and adds a small set of changes on top. Each change lands as its
own PR and its own release, so the delta to upstream is visible in the
[releases](https://github.com/chidambaram27/mcp-auth-proxy/releases) list.

- **Versioning**: `vX.Y.Z-fork.N` — `X.Y.Z` is the upstream release the fork is based on, `N` counts
  fork releases on top of it (reset to `1` after rebasing onto a new upstream release).
- **Image**: `ghcr.io/chidambaram27/mcp-auth-proxy:vX.Y.Z-fork.N` (multi-arch amd64/arm64), plus the
  moving tags `fork` and `latest-fork`. There are no `latest`, `main` or bare semver tags.
- **Releases**: created manually with
  `gh release create vX.Y.Z-fork.N -R chidambaram27/mcp-auth-proxy --target main --generate-notes`;
  publishing the release builds and pushes the image and attaches binaries.
- `mcp-auth-proxy --version` prints the release tag the binary was built from.

| Release | Change |
| ------- | ------ |
| _unreleased_ | Fork CI/release plumbing (this section, image tags, `--version`) |
