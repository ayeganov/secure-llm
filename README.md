# secure-llm

Security sandbox wrapper for agentic AI coding assistants.

[![CI](https://github.com/YOUR_ORG/secure-llm/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/secure-llm/actions/workflows/ci.yml)


## The Problem

AI coding assistants like Claude Code, Cursor, and Windsurf have agentic capabilities that can execute shell commands, modify files, and make network requests. This creates security risks: prompt injection attacks can trick these tools into exfiltrating sensitive data or executing malicious commands. Enterprise environments need visibility and control over what these tools can access.

## Features

- **Sandbox Isolation** - Run AI tools in a bubblewrap container with restricted filesystem access
- **Network Policy** - Allowlist/blocklist/graylist controls for all outbound connections
- **TUI Prompts** - Interactive approval for graylist domains and sensitive operations
- **MITM Proxy** - Transparent HTTPS interception with ephemeral CA for traffic inspection
- **Host Rewriting** - Route LLM API calls through corporate gateways
- **Audit Logging** - Syslog integration for compliance and forensics

## Quick Start

```bash
# Install dependencies
./scripts/install-deps.sh

# Build
cargo build --release

# Run Claude Code in sandbox
./target/release/secure-llm claude
```

## Supported Tools

| Tool | Binary | Description |
|------|--------|-------------|
| Claude Code | `claude` | Anthropic's CLI coding assistant |
| Cursor | `cursor` | AI-powered IDE |
| Windsurf | `windsurf` | Codeium's AI IDE |
| Gemini CLI | `gemini` | Google's CLI assistant |

## Installation

### System Requirements

- Linux (kernel 4.6+ with user namespaces)
- bubblewrap (`bwrap`)
- tmux or zellij (for TUI prompts)

### From Source

**Dynamic build:**
```bash
cargo build --release
```

**Static build (portable):**
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Usage

```bash
# Run a tool in sandbox
secure-llm <tool>

# Examples
secure-llm claude              # Run Claude Code
secure-llm cursor              # Run Cursor IDE
secure-llm gemini              # Run Gemini CLI

# Options
secure-llm --config /path/to/config.toml claude
secure-llm --log-level debug claude
```

## Configuration

### File Locations

secure-llm searches for configuration in order:
1. `--config` CLI argument
2. `$HOME/.config/secure-llm/config.toml`
3. `/etc/secure-llm/config.toml`
4. Built-in defaults

### Configuration Reference

```toml
# General settings
[general]
prompt_timeout = 30          # Seconds to wait for TUI prompt response
log_level = "info"           # trace, debug, info, warn, error

# Corporate gateway (optional)
[gateway]
url = "https://llm-gateway.corp"
timeout_ms = 150

# Environment variables injected into sandbox
# These configure the proxy and CA certificate
[sandbox.env]
HTTP_PROXY = "${SANDBOX_PROXY}"
HTTPS_PROXY = "${SANDBOX_PROXY}"
SSL_CERT_FILE = "${SANDBOX_CA_CERT}"
NODE_EXTRA_CA_CERTS = "${SANDBOX_CA_CERT}"
REQUESTS_CA_BUNDLE = "${SANDBOX_CA_CERT}"

# Network access control
[network]
# Always allowed - no prompt required
allowlist = [
    "pypi.org", "*.pypi.org",
    "registry.npmjs.org",
    "github.com", "api.github.com",
]

# Always blocked - connection refused
blocklist = []

# Prompts user for approval
graylist = [
    "raw.githubusercontent.com",
    "pastebin.com",
]

# Rewrite hosts to route through corporate gateway
[network.host_rewrite]
"api.anthropic.com" = "llm-gateway.corp/v1/anthropic"
"api.openai.com" = "llm-gateway.corp/v1/openai"

# Filesystem restrictions (global)
[filesystem]
denylist = []                # Paths to block access to
bind_ro = []                 # Additional read-only mounts
bind_rw = []                 # Additional read-write mounts

# Per-tool configuration
[tools.claude]
binary = "claude"            # Path to executable
display_name = "Claude Code" # Name shown in prompts
allowlist = ["*.anthropic.com"]  # Tool-specific allowed domains
bind_rw = ["$HOME"]          # Directories tool can write to

[tools.cursor]
binary = "cursor"
display_name = "Cursor IDE"
allowlist = ["*.cursor.sh"]

# Tool-specific host rewrites
[tools.cursor.host_rewrite]
"api.cursor.sh" = "llm-gateway.corp/v1/cursor"
```

### Key Configuration Sections

**`[network]`** - Control which domains can be accessed:
- `allowlist` - Always allowed (package registries, git hosts)
- `blocklist` - Always blocked (known bad domains)
- `graylist` - Prompts user for approval (raw file hosts, paste sites)

**`[network.host_rewrite]`** - Route LLM API calls through corporate infrastructure:
```toml
"api.anthropic.com" = "gateway.corp/v1/anthropic"
```

**`[tools.<name>]`** - Per-tool settings override globals:
- `binary` - Path to executable
- `allowlist` - Additional domains for this tool
- `bind_rw` - Directories the tool can write to

**`[sandbox.env]`** - Environment variables for proxy/CA configuration

## Security Model

### Fail-Closed Policy

All network requests are denied by default. Only explicitly allowed domains can be accessed. Unknown domains trigger a user prompt or are blocked.

### Policy Evaluation Order

1. **Blocklist** - If domain matches, block immediately
2. **Tool allowlist** - If domain matches tool-specific allowlist, allow
3. **Global allowlist** - If domain matches global allowlist, allow
4. **Graylist** - If domain matches, prompt user for approval
5. **Default deny** - Block all other requests

### Ephemeral CA

secure-llm generates a unique CA certificate for each session. This certificate is:
- Created at startup, destroyed at exit
- Injected into the sandbox via environment variables
- Used by the MITM proxy to inspect HTTPS traffic
- Never written to persistent storage

This ensures the proxy can inspect traffic while limiting the CA's lifetime and scope.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Host System                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    secure-llm                          │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │ │
│  │  │ TUI      │  │ MITM     │  │ Policy Engine        │ │ │
│  │  │ Prompts  │←→│ Proxy    │←→│ allow/block/graylist │ │ │
│  │  └──────────┘  └────┬─────┘  └──────────────────────┘ │ │
│  └─────────────────────┼──────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────────────┼──────────────────────────────────┐ │
│  │     bubblewrap      │         Sandbox                   │ │
│  │                     ↓                                   │ │
│  │  ┌──────────────────────────────────────────────────┐  │ │
│  │  │  AI Tool (claude, cursor, etc.)                  │  │ │
│  │  │                                                  │  │ │
│  │  │  HTTP_PROXY=localhost:8080                       │  │ │
│  │  │  SSL_CERT_FILE=/tmp/ca.pem                       │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                              │
                              ↓
                    ┌─────────────────┐
                    │ Internet /      │
                    │ Corp Gateway    │
                    └─────────────────┘
```

## Development

```bash
# Run tests
cargo test

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt

# Security audit
cargo audit
```

## License

MIT License - see [LICENSE](LICENSE) for details.
