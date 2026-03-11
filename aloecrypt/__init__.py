# ./aloecrypt/__init__.py
# License: Apache-2.0 (disclaimer at bottom of file)
import extism
import msgpack
from aloecrypt._plugin import _pack, _unpack, _Plugin, _PluginModel
from aloecrypt.signatory import DilithiumVerifier
from aloecrypt.signatory import DilithiumSigner
from aloecrypt.kem import KyberFullKEM
from aloecrypt.kem import KyberPublicKEM
from aloecrypt.session.builder import SessionBuilder as SessionBuilder
from aloecrypt.session.builder import PartyCHALLENGE as PartyCHALLENGE
from aloecrypt.session.builder import PartyCIPHER as PartyCIPHER
from aloecrypt.session.builder import PartyChallenge as PartyChallenge
from aloecrypt.session.builder import PartyINTRO as PartyINTRO
from aloecrypt.session.builder import PartyRESPONSE as PartyRESPONSE
from aloecrypt.session.builder import PartySecret as PartySecret
from aloecrypt.session.builder import FullCIPHER as FullCIPHER
from aloecrypt.session.message import MsgACK as MsgACK
from aloecrypt.session.message import MsgHELLO as MsgHELLO
from aloecrypt.session.message import MsgSYN as MsgSYN
from aloecrypt.session.message import MsgSYNACK as MsgSYNACK
from aloecrypt.session.message import MsgWELCOME as MsgWELCOME
from aloecrypt.session import AloecryptSession as AloecryptSession
from aloecrypt.session import CounterParty as CounterParty
from aloecrypt.session import Party as Party

# plugin = _Plugin(".bin/aloecrypt_plugin2.wasm")
plugin = _Plugin()


class FromSecretsInput(_PluginModel):
    stable_secret_a: bytes
    session_secret_a: bytes
    signature_a: bytes
    nonce_a: bytes
    address_a: bytes
    stable_secret_b: bytes
    session_secret_b: bytes
    signature_b: bytes
    nonce_b: bytes
    address_b: bytes
    session_salt: bytes


# ── DilithiumSigner ──────────────────────────────────────────────────────────


@classmethod
def dilithium_signer_new(cls) -> DilithiumSigner:
    return DilithiumSigner(**_unpack(plugin.call("dilithium_signer_new", b"")))


def dilithium_signer_into_verifier(self) -> DilithiumVerifier:
    return DilithiumVerifier(
        **_unpack(plugin.call("dilithium_signer_into_verifier", _pack(self)))
    )


def dilithium_signer_address(self) -> bytes:
    return plugin.call("dilithium_signer_address", _pack(self))


def dilithium_signer_is_root(self) -> bool:
    return bool(plugin.call("dilithium_signer_is_root", _pack(self))[0])


def dilithium_signer_is_time_active(self) -> bool:
    return bool(plugin.call("dilithium_signer_is_time_active", _pack(self))[0])


def dilithium_signer_sign(self, message: bytes) -> bytes:
    return plugin.call("dilithium_signer_sign", _pack(self, message))


def dilithium_signer_sign_hex(self, message: bytes) -> str:
    return self.sign(message).hex()


def dilithium_signer_to_x_pem(self, password: bytes, salt: bytes) -> str:
    return plugin.call(
        "dilithium_signer_to_x_pem", _pack(self, password, salt)
    ).decode()


@classmethod
def dilithium_signer_from_x_pem(
    cls, pem: str, password: bytes, salt: bytes
) -> DilithiumSigner:
    return DilithiumSigner(
        **_unpack(
            plugin.call("dilithium_signer_from_x_pem", _pack(pem, password, salt))
        )
    )


def dilithium_signer_create_delegate(
    self,
    active_from: bytes,
    expires_at: bytes,
    refresh_count: int,
    max_refresh: int,
) -> DilithiumSigner:
    return DilithiumSigner(
        **_unpack(
            plugin.call(
                "dilithium_signer_create_delegate",
                _pack(
                    self,
                    bytes(active_from),
                    bytes(expires_at),
                    refresh_count,
                    max_refresh,
                ),
            )
        )
    )


def dilithium_signer_signing_material(self) -> bytes:
    return plugin.call("dilithium_signer_signing_material", _pack(self))


def dilithium_signer_signing_auth_id(self) -> bytes:
    return plugin.call("dilithium_signer_signing_auth_id", _pack(self))


@property
def dilithium_signer_address(self) -> bytes:
    return plugin.call("dilithium_signer_address", _pack(self))


@property
def dilithium_signer_auth_id(self) -> bytes:
    return plugin.call("dilithium_signer_auth_id", _pack(self))


DilithiumSigner.new = dilithium_signer_new
DilithiumSigner.auth_id = dilithium_signer_auth_id
DilithiumSigner.address = dilithium_signer_address
DilithiumSigner.to_verifier = dilithium_signer_into_verifier
DilithiumSigner.signing_address = dilithium_signer_address
DilithiumSigner.is_root = dilithium_signer_is_root
DilithiumSigner.is_time_active = dilithium_signer_is_time_active
DilithiumSigner.sign = dilithium_signer_sign
DilithiumSigner.sign_hex = dilithium_signer_sign_hex
DilithiumSigner.to_x_pem = dilithium_signer_to_x_pem
DilithiumSigner.from_x_pem = dilithium_signer_from_x_pem
DilithiumSigner.create_delegate = dilithium_signer_create_delegate
DilithiumSigner.signing_material = dilithium_signer_signing_material
DilithiumSigner.signing_auth_id = dilithium_signer_signing_auth_id


# ── DilithiumVerifier ────────────────────────────────────────────────────────


def dilithium_verifier_verify(self, material: bytes, sig_bytes: bytes) -> bool:
    return bool(
        plugin.call("dilithium_verifier_verify", _pack(self, material, sig_bytes))[0]
    )


def dilithium_verifier_is_root(self) -> bool:
    return bool(plugin.call("dilithium_verifier_is_root", _pack(self))[0])


def dilithium_verifier_is_time_active(self) -> bool:
    return bool(plugin.call("dilithium_verifier_is_time_active", _pack(self))[0])


def dilithium_verifier_to_pem(self) -> str:
    return plugin.call("dilithium_verifier_to_pem", _pack(self)).decode()


@classmethod
def dilithium_verifier_from_pem(cls, pem: str) -> DilithiumVerifier:
    return DilithiumVerifier(
        **_unpack(plugin.call("dilithium_verifier_from_pem", pem.encode()))
    )


def dilithium_verifier_signing_material(self) -> bytes:
    return plugin.call("dilithium_verifier_signing_material", _pack(self))


def dilithium_verifier_signing_auth_id(self) -> bytes:
    return plugin.call("dilithium_verifier_signing_auth_id", _pack(self))


@property
def dilithium_verifier_address(self) -> bytes:
    return plugin.call("dilithium_verifier_address", _pack(self))


@property
def dilithium_verifier_auth_id(self) -> bytes:
    return plugin.call("dilithium_verifier_auth_id", _pack(self))


DilithiumVerifier.auth_id = dilithium_verifier_auth_id
DilithiumVerifier.address = dilithium_verifier_address
DilithiumVerifier.verify = dilithium_verifier_verify
DilithiumVerifier.is_root = dilithium_verifier_is_root
DilithiumVerifier.is_time_active = dilithium_verifier_is_time_active
DilithiumVerifier.to_pem = dilithium_verifier_to_pem
DilithiumVerifier.from_pem = dilithium_verifier_from_pem
DilithiumVerifier.signing_material = dilithium_verifier_signing_material
DilithiumVerifier.signing_auth_id = dilithium_verifier_signing_auth_id


# ── KyberFullKEM ─────────────────────────────────────────────────────────────


@classmethod
def kyber_kem_new(
    cls,
    signer: DilithiumSigner,
    active_from: bytes,
    expires_at: bytes,
    refresh_count: int,
    max_refresh: int,
) -> KyberFullKEM:
    return KyberFullKEM(
        **_unpack(
            plugin.call(
                "kyber_kem_new",
                _pack(
                    signer,
                    bytes(active_from),
                    bytes(expires_at),
                    refresh_count,
                    max_refresh,
                ),
            )
        )
    )


@classmethod
def kyber_kem_canonical(
    cls,
    signer: DilithiumSigner,
    idx: bytes,
    active_from: bytes,
    expires_at: bytes,
    refresh_count: int,
    max_refresh: int,
) -> KyberFullKEM:
    return KyberFullKEM(
        **_unpack(
            plugin.call(
                "kyber_kem_canonical",
                _pack(
                    signer,
                    idx,
                    bytes(active_from),
                    bytes(expires_at),
                    refresh_count,
                    max_refresh,
                ),
            )
        )
    )


def kyber_kem_into_public(self) -> KyberPublicKEM:
    return KyberPublicKEM(**_unpack(plugin.call("kyber_kem_into_public", _pack(self))))


def kyber_kem_to_x_pem(self, password: bytes, salt: bytes) -> str:
    return plugin.call("kyber_kem_to_x_pem", _pack(self, password, salt)).decode()


@classmethod
def kyber_kem_from_x_pem(cls, pem: str, password: bytes, salt: bytes) -> KyberFullKEM:
    return KyberFullKEM(
        **_unpack(plugin.call("kyber_kem_from_x_pem", _pack(pem, password, salt)))
    )


def kyber_kem_signing_material(self) -> bytes:
    return plugin.call("kyber_kem_signing_material", _pack(self))


@property
def kyber_kem_address(self) -> bytes:
    return plugin.call("kyber_kem_address", _pack(self))


@property
def kyber_kem_auth_id(self) -> bytes:
    return plugin.call("kyber_kem_auth_id", _pack(self))


KyberFullKEM.auth_id = kyber_kem_auth_id
KyberFullKEM.address = kyber_kem_address
KyberFullKEM.create = kyber_kem_new
KyberFullKEM.canonical = kyber_kem_canonical
KyberFullKEM.to_public = kyber_kem_into_public
KyberFullKEM.to_x_pem = kyber_kem_to_x_pem
KyberFullKEM.from_x_pem = kyber_kem_from_x_pem
KyberFullKEM.signing_material = kyber_kem_signing_material

# ── KyberPublicKEM ───────────────────────────────────────────────────────────


def kyber_full_kem_decapsulate(self, ciphertext: bytes) -> bytes:
    return plugin.call("kyber_full_kem_decapsulate", _pack(self, list(ciphertext)))


KyberFullKEM.decapsulate = kyber_full_kem_decapsulate


def kyber_public_kem_to_pem(self) -> str:
    return plugin.call("kyber_public_kem_to_pem", _pack(self)).decode()


@classmethod
def kyber_public_kem_from_pem(cls, pem: str) -> KyberPublicKEM:
    return KyberPublicKEM(
        **_unpack(plugin.call("kyber_public_kem_from_pem", pem.encode()))
    )


def kyber_public_kem_signing_material(self) -> bytes:
    return plugin.call("kyber_public_kem_signing_material", _pack(self))


@property
def kyber_public_kem_address(self) -> bytes:
    return plugin.call("kyber_public_kem_address", _pack(self))


@property
def kyber_public_kem_auth_id(self) -> bytes:
    return plugin.call("kyber_public_kem_auth_id", _pack(self))


KyberPublicKEM.to_pem = kyber_public_kem_to_pem
KyberPublicKEM.from_pem = kyber_public_kem_from_pem
KyberPublicKEM.signing_material = kyber_public_kem_signing_material
KyberPublicKEM.auth_id = kyber_public_kem_auth_id
KyberPublicKEM.address = kyber_public_kem_address


def kyber_public_kem_encapsulate(self) -> tuple[bytes, bytes]:
    result = _unpack(plugin.call("kyber_public_kem_encapsulate", _pack(self)))
    return bytes(result[0]), bytes(result[1])


KyberPublicKEM.encapsulate = kyber_public_kem_encapsulate

# ── SessionBuilder ───────────────────────────────────────────────────────────


@classmethod
def session_builder_new(
    cls, counterparty_address: bytes, delegate_signer: DilithiumSigner
) -> SessionBuilder:
    return SessionBuilder(
        **_unpack(
            plugin.call(
                "session_builder_new",
                _pack(bytes(counterparty_address), delegate_signer),
            )
        )
    )


@property
def session_builder_address(self) -> bytes:
    return plugin.call("session_builder_address", _pack(self))


def session_builder_make_party_intro(self) -> PartyINTRO:
    return PartyINTRO(
        **_unpack(plugin.call("session_builder_make_party_intro", _pack(self)))
    )


def _rebuild_session_builder(self, data: dict):
    """Reconstruct self from normalised dict by going through Pydantic
    validation, then swapping the internal __dict__."""
    new = SessionBuilder(**data)
    self.__dict__.update(new.__dict__)
    return self


def session_builder_on_counterparty_intro(self, intro: PartyINTRO) -> "SessionBuilder":
    data = _unpack(
        plugin.call("session_builder_on_counterparty_intro", _pack(self, intro))
    )
    return _rebuild_session_builder(self, data)


def session_builder_make_party_cipher(self) -> PartyCIPHER:
    return PartyCIPHER(
        **_unpack(plugin.call("session_builder_make_party_cipher", _pack(self)))
    )


def session_builder_on_counterparty_cipher(
    self, cipher: PartyCIPHER
) -> "SessionBuilder":
    data = _unpack(
        plugin.call("session_builder_on_counterparty_cipher", _pack(self, cipher))
    )
    return _rebuild_session_builder(self, data)


def session_builder_make_party_challenge(self) -> PartyCHALLENGE:
    return PartyCHALLENGE(
        **_unpack(plugin.call("session_builder_make_party_challenge", _pack(self)))
    )


def session_builder_on_counterparty_challenge(
    self, challenge: PartyCHALLENGE
) -> "SessionBuilder":
    data = _unpack(
        plugin.call("session_builder_on_counterparty_challenge", _pack(self, challenge))
    )
    return _rebuild_session_builder(self, data)


def session_builder_make_party_challenge_response(self) -> PartyRESPONSE:
    return PartyRESPONSE(
        **_unpack(
            plugin.call("session_builder_make_party_challenge_response", _pack(self))
        )
    )


def session_builder_on_counterparty_challenge_response(
    self, response: PartyRESPONSE
) -> "SessionBuilder":
    data = _unpack(
        plugin.call(
            "session_builder_on_counterparty_challenge_response", _pack(self, response)
        )
    )
    return _rebuild_session_builder(self, data)


def session_builder_build(self) -> AloecryptSession:
    return AloecryptSession(
        **_unpack(plugin.call("session_builder_build", _pack(self)))
    )


SessionBuilder.create = session_builder_new
SessionBuilder.address = session_builder_address
SessionBuilder.make_party_intro = session_builder_make_party_intro
SessionBuilder.on_counterparty_intro = session_builder_on_counterparty_intro
SessionBuilder.make_party_cipher = session_builder_make_party_cipher
SessionBuilder.on_counterparty_cipher = session_builder_on_counterparty_cipher
SessionBuilder.make_party_challenge = session_builder_make_party_challenge
SessionBuilder.on_counterparty_challenge = session_builder_on_counterparty_challenge
SessionBuilder.make_party_challenge_response = (
    session_builder_make_party_challenge_response
)
SessionBuilder.on_counterparty_challenge_response = (
    session_builder_on_counterparty_challenge_response
)
SessionBuilder.build = session_builder_build


# ── AloecryptSession ─────────────────────────────────────────────────────────


@classmethod
def session_from_secrets(
    cls,
    stable_secret_a: bytes,
    session_secret_a: bytes,
    signature_a: bytes,
    nonce_a: bytes,
    address_a: bytes,
    stable_secret_b: bytes,
    session_secret_b: bytes,
    signature_b: bytes,
    nonce_b: bytes,
    address_b: bytes,
    session_salt: bytes,
) -> "AloecryptSession":
    payload = FromSecretsInput(
        stable_secret_a=stable_secret_a,
        session_secret_a=session_secret_a,
        signature_a=signature_a,
        nonce_a=nonce_a,
        address_a=address_a,
        stable_secret_b=stable_secret_b,
        session_secret_b=session_secret_b,
        signature_b=signature_b,
        nonce_b=nonce_b,
        address_b=address_b,
        session_salt=session_salt,
    )
    return AloecryptSession(
        **_unpack(plugin.call("session_from_secrets", _pack(payload)))
    )


def session_encrypt(self, plaintext: bytes) -> bytes:
    return plugin.call("session_encrypt", _pack(self, plaintext))


def session_decrypt(self, ciphertext: bytes) -> bytes:
    return plugin.call("session_decrypt", _pack(self, ciphertext))


AloecryptSession.encrypt = session_encrypt
AloecryptSession.decrypt = session_decrypt
AloecryptSession.from_secrets = session_from_secrets

# ── Convenience: full handshake ──────────────────────────────────────────────


def perform_handshake(
    session_a: SessionBuilder, session_b: SessionBuilder
) -> tuple[AloecryptSession, AloecryptSession]:
    """
    Runs the full HELLO -> SYN -> ACK -> SYNACK -> WELCOME handshake between
    two SessionBuilder instances, mutating both in place, and returns the
    two built AloecryptSession objects.
    """
    # A -> B: HELLO
    intro_a = session_a.make_party_intro()
    session_b.on_counterparty_intro(intro_a)

    # B -> A: SYN
    intro_b = session_b.make_party_intro()
    cipher_b = session_b.make_party_cipher()
    session_a.on_counterparty_intro(intro_b)
    session_a.on_counterparty_cipher(cipher_b)

    # A -> B: ACK
    cipher_a = session_a.make_party_cipher()
    challenge_a = session_a.make_party_challenge()
    session_b.on_counterparty_cipher(cipher_a)
    session_b.on_counterparty_challenge(challenge_a)

    # B -> A: SYNACK
    challenge_b = session_b.make_party_challenge()
    response_b = session_b.make_party_challenge_response()
    session_a.on_counterparty_challenge(challenge_b)
    session_a.on_counterparty_challenge_response(response_b)

    # A -> B: WELCOME
    response_a = session_a.make_party_challenge_response()
    session_b.on_counterparty_challenge_response(response_a)

    # Build
    built_a = session_a.build()
    built_b = session_b.build()
    return (
        built_a,
        built_b,
    )  # Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>


#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
