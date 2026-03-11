# Quickstart

## Installation
```bash
pip install aloecrypt
```

## Concepts

Every party has:

- A **root signer** (`DilithiumSigner`) — the stable identity anchor. Keep this offline or persisted securely.
- A **delegate signer** — a short-lived keypair derived from the root, used for active sessions.
- A **SessionBuilder** — drives the handshake with a specific counterparty.
- An **AloecryptSession** — the result of a completed handshake, used to encrypt and decrypt messages.

The address is a 32-byte value derived from the root signer. It identifies a
party across sessions and delegates.

---

## Standard handshake

The typical flow for two parties that can exchange messages directly.
```python
from aloecrypt import DilithiumSigner, SessionBuilder, perform_handshake
from aloecrypt.consts import EMPTY_TIMESTAMP

# Each party generates a root identity (done once, then persisted)
root_a = DilithiumSigner.new()
root_b = DilithiumSigner.new()

# Derive delegates for this session
delegate_a = root_a.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
delegate_b = root_b.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

# Each party creates a SessionBuilder targeting the other's address
session_a = SessionBuilder.create(root_b.address, delegate_a)
session_b = SessionBuilder.create(root_a.address, delegate_b)

# Run the full handshake (both parties in the same process — useful for testing)
built_a, built_b = perform_handshake(session_a, session_b)

# Encrypt and decrypt
ciphertext = built_a.encrypt(b"hello from A")
plaintext  = built_b.decrypt(ciphertext)
assert plaintext == b"hello from A"
```

---

## Handshake over a real transport

In production, parties are in separate processes. Each `make_*` call produces
a message to send; each `on_counterparty_*` call consumes a message received.
Serialise the message objects however suits your transport (msgpack, protobuf,
JSON, etc.).
```python
# Party A — initiator
session_a = SessionBuilder.create(address_b, delegate_a)

# HELLO — send to B
msg_hello = session_a.make_party_intro()
transport.send(msg_hello)

# SYN — receive from B
msg_syn_intro, msg_syn_cipher = transport.recv()
session_a.on_counterparty_intro(msg_syn_intro)
session_a.on_counterparty_cipher(msg_syn_cipher)

# ACK — send to B
transport.send(session_a.make_party_cipher())
transport.send(session_a.make_party_challenge())

# SYNACK — receive from B
msg_challenge_b, msg_response_b = transport.recv()
session_a.on_counterparty_challenge(msg_challenge_b)
session_a.on_counterparty_challenge_response(msg_response_b)

# WELCOME — send to B
transport.send(session_a.make_party_challenge_response())

built_a = session_a.build()
```
```python
# Party B — responder (mirror of the above)
session_b = SessionBuilder.create(address_a, delegate_b)

# HELLO — receive from A
session_b.on_counterparty_intro(transport.recv())

# SYN — send to A
transport.send(session_b.make_party_intro())
transport.send(session_b.make_party_cipher())

# ACK — receive from A
session_b.on_counterparty_cipher(transport.recv())
session_b.on_counterparty_challenge(transport.recv())

# SYNACK — send to A
transport.send(session_b.make_party_challenge())
transport.send(session_b.make_party_challenge_response())

# WELCOME — receive from A
session_b.on_counterparty_challenge_response(transport.recv())

built_b = session_b.build()
```

---

## Custom sessions from pre-shared secrets

If you have established shared secrets through your own protocol, you can
construct a session directly without running the handshake. Both parties must
call `from_secrets` with their own secrets first and the counterparty's secrets
second.
```python
from aloecrypt import AloecryptSession
import os

# Both parties must agree on these values out of band
stable_secret_a  = os.urandom(32)
session_secret_a = os.urandom(32)
stable_secret_b  = os.urandom(32)
session_secret_b = os.urandom(32)
signature_a      = os.urandom(3309)
signature_b      = os.urandom(3309)
nonce_a          = os.urandom(32)
nonce_b          = os.urandom(32)
address_a        = os.urandom(32)
address_b        = os.urandom(32)
session_salt     = os.urandom(32)

session_a = AloecryptSession.from_secrets(
    stable_secret_a, session_secret_a, signature_a, nonce_a, address_a,
    stable_secret_b, session_secret_b, signature_b, nonce_b, address_b,
    session_salt,
)
session_b = AloecryptSession.from_secrets(
    stable_secret_b, session_secret_b, signature_b, nonce_b, address_b,
    stable_secret_a, session_secret_a, signature_a, nonce_a, address_a,
    session_salt,
)

ciphertext = session_a.encrypt(b"hello")
assert session_b.decrypt(ciphertext) == b"hello"
```

---

## Persisting identities

Root signers and KEM keys can be serialised to PEM for storage.
```python
from aloecrypt import DilithiumSigner, KyberFullKEM
from aloecrypt.consts import EMPTY_TIMESTAMP

password = b"your-password"
salt     = b"your-salt"

root = DilithiumSigner.new()

# Save
root_pem = root.to_x_pem(password, salt)

# Load
loaded_root = DilithiumSigner.from_x_pem(root_pem, password, salt)

# Share the verifier publicly
verifier_pem = loaded_root.to_verifier().to_pem()

# Save a KEM key
kem = KyberFullKEM.create(
    loaded_root.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0),
    EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0,
)
kem_pem = kem.to_x_pem(password, salt)
loaded_kem = KyberFullKEM.from_x_pem(kem_pem, password, salt)
```

---

## Building the docs locally
```bash
pip install ".[docs]"
mkdocs serve
```
