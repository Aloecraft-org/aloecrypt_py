# aloecrypt-py

<div align="center">

<img src="docs/icon.png" style="height:96px; width:96px;"/>

**A post-quantum secure messaging library for Python**

[![GitHub](https://img.shields.io/badge/GitHub-%23121011.svg?logo=github&logoColor=white)](https://github.com/aloecraft/aloecrypt_plugin)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

</div>

Aloecrypt provides mutual authentication and encrypted sessions using
ML-KEM-768 (Kyber) for key encapsulation and ML-DSA-65 (Dilithium) for
signatures, with ChaCha20-Poly1305 for symmetric encryption. The
cryptographic core is compiled to WebAssembly, so there are no native
extension dependencies.

## Installation
```bash
pip install aloecrypt
```

Requires Python 3.11 or later.

## Quick example
```python
from aloecrypt import DilithiumSigner, SessionBuilder, perform_handshake
from aloecrypt.consts import EMPTY_TIMESTAMP

# Each party creates a root identity (done once, then persisted)
root_a = DilithiumSigner.new()
root_b = DilithiumSigner.new()

# Derive short-lived delegates for active use
delegate_a = root_a.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
delegate_b = root_b.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

# Build sessions targeting each other's address
session_a = SessionBuilder.create(root_b.address, delegate_a)
session_b = SessionBuilder.create(root_a.address, delegate_b)

# Run the handshake
built_a, built_b = perform_handshake(session_a, session_b)

# Encrypt and decrypt
ciphertext = built_a.encrypt(b"hello")
assert built_b.decrypt(ciphertext) == b"hello"
```

## What it provides

- **Identities** -- ML-DSA-65 root keypairs with derived short-lived delegates.
  The root key can be kept offline; delegates are used for active sessions.
- **Key encapsulation** -- ML-KEM-768 keypairs signed by a delegate. Direct
  encapsulate/decapsulate is available for custom protocols.
- **Handshake** -- a five-message mutual proof-of-decryption protocol.
  Transport-agnostic; works over TCP, WebRTC, HTTP, message queues, or
  anything else.
- **Sessions** -- ChaCha20-Poly1305 authenticated encryption with
  deterministic nonce derivation. Supports arbitrary byte payloads including
  empty and large messages.
- **Custom sessions** -- construct a session directly from pre-shared secrets
  without running the handshake, for integration with your own key agreement
  protocol.
- **PEM serialisation** -- encrypted PEM for private keys, unencrypted PEM
  for public keys and verifiers.

## Algorithms

| Role | Algorithm |
|---|---|
| Signing | ML-DSA-65 (Dilithium) |
| Key encapsulation | ML-KEM-768 (Kyber) |
| Symmetric encryption | ChaCha20-Poly1305 |
| Key derivation | HKDF-SHA256 |
| Key stretching | PBKDF2 |

## Documentation

Full API reference and usage guides at
[aloecrypt-py.aloecraft.org](https://aloecrypt-py.aloecraft.org).

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.

Copyright Michael Godfrey 2026 | [aloecraft.org](https://aloecraft.org)