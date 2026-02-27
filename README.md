# seshador — Secrets sharing done right

**Secure, ephemeral secret sharing for organizations and teams**

## Why seshador exists

In many organizations, teams need to share sensitive information (API keys, passwords, database credentials, one-time tokens, private files, etc.) quickly and securely.

The most common ways people currently do this are insecure or problematic:

- Pasting plaintext secrets into Slack / Microsoft Teams / WhatsApp / email → logged forever, searchable, visible to admins, exported in backups
- Using third-party one-time-secret services (1Password Send, Bitwarden Send, onetimesecret.com) → secrets leave your infrastructure, provider can see metadata, long-term retention risk
- Attaching encrypted files to chat → still requires sharing decryption keys/passwords in the same channel → defeats the purpose

**seshador solves this by combining:**
- End-to-end encryption using ephemeral X25519 Diffie-Hellman key exchange + AES-256-GCM
- No plaintext secrets ever touch the messaging platform
- Organization-controlled temporary storage (your own vault server)
- Strong authentication for retrieval (Ed25519 signature)
- Automatic deletion after first access or expiry
- Zero-knowledge design: the vault never sees the plaintext secret or the encryption key

The result: you can safely coordinate secret sharing through your existing internal chat (even if admins can read history), while keeping the actual sensitive payload in a system you control.

## What problem does it solve?

**Core problem**:
Safe, asynchronous secret sharing between two parties when the communication channel (chat, email, ticketing system) is **not fully trusted** for plaintext secrets, but **is trusted for integrity** (messages can't be silently modified).

**Typical use cases**:
- Sending temporary credentials to a coworker
- Sharing one-time recovery codes or setup tokens
- Transferring service account keys between teams
- Sending private keys or certificates during onboarding
- Any situation where pasting the secret directly into chat feels risky

## Key security properties

- **Forward secrecy** — every secret share uses fresh ephemeral keys
- **Confidentiality** — only sender and receiver can decrypt (vault is blind)
- **Authentication** — receiver must prove possession of the correct Ed25519 key
- **One-time use** — secret is deleted after first successful retrieval
- **Replay protection** — server challenge + tight timestamp window
- **Integrity** — AES-GCM + Ed25519 signatures

## Assumptions and intended usage

seshador is designed under these assumptions:

1. **The chat/messaging channel provides integrity**
   → Messages cannot be silently modified by a third party (active MITM is not possible).
   → Eavesdropping is acceptable (public keys and challenge are not secret).

2. **Usage is low-volume and short-lived**
   → Secrets are shared infrequently and retrieved quickly (minutes to hours).
   → Not designed for long-term storage or high-throughput secrets management.

3. **No mutual authentication between owner and receiver is required**
   → The protocol does not prevent a malicious receiver from initiating a share.
   → Trust comes from out-of-band identity verification (e.g., knowing who sent the initial code).

If any of these assumptions do not hold in your environment, seshador may not be the right tool.

## Architecture overview

```
[Receiver] ──(chat)──► Initial message (X25519 pub + Ed25519 pub)
                      │
                      ▼
[Owner]     ◄─────────┘
   │
   ▼
Computes shared secret → derives secretID + enc key
Encrypts secret → uploads to Vault (POST /secrets)
   │
   ▼
Receives challenge from Vault → sends to Receiver via chat (X25519 pub + challenge)
                      │
                      ▼
[Receiver] computes same secretID + enc key
Requests secret from Vault (GET /secrets/{secretID}?msg=...&sig=...)
   │
   ▼
Vault validates signature + challenge → returns encrypted secret → deletes
   │
   ▼
Receiver decrypts → gets plaintext secret
```

## Features

- Ephemeral X25519 DH + Ed25519 authentication
- AES-256-GCM encryption with random nonce
- HKDF key derivation with domain separation
- Server-side challenge for replay protection
- Automatic deletion after retrieval
- 24-hour fallback expiry
- Optional TLS with custom CA support
- In-memory or DynamoDB backend (via `--storage` URI)

## Installation

```bash
go install github.com/artilugio0/seshador/cmd/seshador@latest
```

Or clone and build:

```bash
git clone https://github.com/artilugio0/seshador.git
cd seshador
go build -o seshador ./cmd/seshador
```

## Quick start

1. **Run vault** (in-memory mode)

```bash
seshador vault --listen :8443 --tls-cert server.crt --tls-key server.key
# or insecure (for local testing):
seshador vault --listen :8080 --insecure-no-tls
```

2. **Receiver** generates initial message

```bash
seshador receive --vault-url https://your-vault:8443
# Outputs base64 message → send to Owner via chat
```

3. **Owner** receives message, encrypts secret

```bash
seshador share "my-very-secret-password" --vault-url https://your-vault:8443
# Paste receiver's message when prompted
# Outputs new base64 message → send back to Receiver
```

4. **Receiver** retrieves and decrypts

```bash
# Paste owner's message when prompted
# Secret is printed to stdout
```

## License

MIT

## Contributing

Pull requests welcome! Especially:
- Additional backends (Redis, PostgreSQL, SQLite)
- Better error messages / HTTP status codes
- Rate limiting middleware
- Metrics
- Testing

## Acknowledgments

Inspired by:
- Yopass
- Magic Wormhole
