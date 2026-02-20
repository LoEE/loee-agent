# loee-agent

A macOS SSH agent with per-session user approval for forwarded signing requests.

Built in Swift with no external dependencies — uses CryptoKit for cryptography, Keychain for key storage, and Secure Enclave for hardware-backed keys.

## Why

Standard `ssh-agent` forwarding gives any remote host silent access to all your keys. This agent splits that into two sockets:

- **Local socket** — auto-approves signing (same trust model as normal ssh-agent)
- **Forwarded socket** — shows a native macOS dialog before every signing operation, with verified host information

This means a compromised remote host can't silently use your keys to authenticate elsewhere.

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│ Your Mac                                                        │
│                                                                 │
│  ssh user@host ──► loee-agent-local.sock ──► sign (auto)        │
│                                                                 │
│  System ssh-agent ◄── upstream proxy (merged key listing)       │
│                                                                 │
│  Remote host ──► loee-agent-forwarded.sock ──► NSAlert ──► sign │
│                                                                 │
│  Keys: Keychain (Ed25519, SE P-256) + upstream agent keys       │
└─────────────────────────────────────────────────────────────────┘
```

When a signing request arrives on the forwarded socket, the agent shows a macOS alert with:

- The target hostname (verified against `~/.ssh/known_hosts`)
- The username being authenticated
- Key fingerprint and algorithm
- A warning if the host key doesn't match known_hosts (possible MITM)

## Upstream agent proxying

On startup, the agent captures `SSH_AUTH_SOCK` from the environment and proxies to the existing system ssh-agent. This means keys loaded via `ssh-add` appear alongside Keychain-managed keys — no need to re-add them. Upstream keys on the forwarded socket still require user approval.

## Setup

### Build

```sh
swift build -c release
```

Binaries are in `.build/release/loee-agent` and `.build/release/loee-agent-ctl`.

### Configure SSH

```sh
loee-agent-ctl setup
```

This writes `~/.ssh/loee-agent.conf` and adds `Include loee-agent.conf` to your `~/.ssh/config`:

```
Host *
    IdentityAgent ~/.ssh/loee-agent-local.sock
    ForwardAgent ~/.ssh/loee-agent-forwarded.sock
```

### Run at login

Copy the launchd plist to start the agent automatically:

```sh
cp Resources/pl.loee.ssh-agent.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/pl.loee.ssh-agent.plist
```

## Key management

Generate a new Ed25519 key (stored in Keychain):

```sh
loee-agent-ctl generate
# or with options:
loee-agent-ctl generate --type ed25519 --comment "work laptop"
```

Generate a Secure Enclave P-256 key (hardware-backed, non-exportable):

```sh
loee-agent-ctl generate --type ecdsa-p256
```

List keys:

```sh
loee-agent-ctl list
```

Export a public key:

```sh
loee-agent-ctl export --id <key-id>
```

Delete a key:

```sh
loee-agent-ctl delete --id <key-id>
```

## Session binding

The agent supports a `session-bind@pl.loee` protocol extension. When the SSH client sends host key information through this extension, the agent:

1. Verifies the host key signature cryptographically (Ed25519, ECDSA P-256)
2. Checks the hostname against `~/.ssh/known_hosts`
3. Displays the verified host identity in the approval dialog

This gives you confidence about *which host* is requesting authentication, not just that *some host* is requesting it.

## Architecture

```
Sources/
├── SSHAgent/                    # Agent daemon
│   ├── main.swift               # Startup, socket creation, upstream capture
│   ├── AgentServer.swift        # Unix domain socket server (GCD-based)
│   ├── AgentConnectionHandler.swift  # Per-connection message framing
│   ├── AgentRequestHandler.swift     # Request dispatch, upstream forwarding
│   ├── UpstreamAgent.swift      # Client for proxying to system ssh-agent
│   └── UserApproval.swift       # NSAlert approval dialog
├── SSHAgentCtl/                 # CLI tool
│   ├── main.swift
│   └── Commands.swift           # generate, list, export, delete, setup
└── SSHAgentLib/                 # Shared library
    ├── SSHWireFormat.swift       # SSH wire encoding/decoding
    ├── SSHAgentProtocol.swift    # Agent protocol messages
    ├── SSHKeyTypes.swift         # SSHKey protocol + Ed25519/P-256 implementations
    ├── KeyStore.swift            # Keychain-backed key storage
    ├── PublicKeyFormats.swift    # Public key blob encoding, fingerprints
    ├── SignatureFormats.swift    # SSH signature wire format
    ├── KnownHosts.swift         # known_hosts parser
    └── HostKeyVerifier.swift    # Host key signature verification
```

## Requirements

- macOS 13+ (Ventura)
- Swift 5.9+
