# Aloecrypt

Aloecrypt is a post-quantum secure messaging library for Python. It provides
mutual authentication and encrypted sessions using ML-KEM-768 (Kyber) for key
encapsulation and ML-DSA-65 (Dilithium) for signatures, with ChaCha20-Poly1305
for symmetric encryption.

The cryptographic core is compiled to WebAssembly and distributed as a WASM
plugin, making the library platform-independent with no native extension
dependencies.

## What it does

- **Identity** — each party has a root ML-DSA-65 signing keypair. Short-lived
  delegates are derived from the root for active use, so the root key can be
  kept offline.
- **Key encapsulation** — ML-KEM-768 keypairs are signed by a delegate and
  bound to the identity. Sessions use two KEM layers (stable + ephemeral) for
  forward secrecy.
- **Handshake** — a five-message protocol establishes mutual proof-of-decryption
  before either party can send application data.
- **Sessions** — once established, sessions encrypt and decrypt arbitrary byte
  payloads with authenticated encryption. Nonces are derived deterministically,
  eliminating reuse.

## When to use it

Aloecrypt is a good fit if you need:

- End-to-end encrypted messaging between identified parties
- Post-quantum resistance for long-lived keys or sensitive data
- A session layer you can integrate into your own transport (TCP, WebRTC, HTTP,
  message queue — Aloecrypt is transport-agnostic)
- Custom session construction from pre-shared secrets, without running the
  full handshake

It is not a drop-in replacement for TLS and does not manage connections,
framing, or retransmission.

## Installation
```bash
pip install aloecrypt
```

Requires Python 3.11 or later.

## Quick links

- [Quickstart](quickstart.md) — working code from zero to encrypted message
- [Session](api/session.md) — `AloecryptSession` reference
- [Builder](api/builder.md) — `SessionBuilder` and handshake protocol reference
- [Signatory](api/signatory.md) — `DilithiumSigner` and `DilithiumVerifier` reference
- [KEM](api/kem.md) — `KyberFullKEM` and `KyberPublicKEM` reference
- [Constants](api/consts.md) — size constants and protocol seeds
