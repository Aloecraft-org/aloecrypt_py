# ./test/test_unit.py
# License: Apache-2.0 (disclaimer at bottom of file)
# Mirrors: tests/custom_session.rs, tests/handshake.rs, tests/pem.rs, tests/pqc.rs

import os
import pytest

import aloecrypt as ac
from aloecrypt import (
    AloecryptSession,
    DilithiumSigner,
    DilithiumVerifier,
    KyberFullKEM,
    KyberPublicKEM,
    SessionBuilder,
    PartyCHALLENGE,
    PartyCIPHER,
    PartyINTRO,
    PartyRESPONSE,
    MsgHELLO,
    MsgSYN,
    MsgACK,
    MsgSYNACK,
    MsgWELCOME,
)

EMPTY_TIMESTAMP = bytes(8)


# ── Helpers ───────────────────────────────────────────────────────────────────


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def make_signer() -> DilithiumSigner:
    return DilithiumSigner.new()

def make_session_pair() -> tuple[AloecryptSession, AloecryptSession]:
    """
    Build a symmetric pair of sessions from fresh random secrets,
    swapping party/counterparty roles between A and B.
    Mirrors: custom_session.rs::make_session_pair
    """
    from aloecrypt.consts import (
        SECRET_SZ,
        SIGNATURE_SZ,
        SESSION_NONCE_SZ,
        ADDRESS_SZ,
        SESSION_SALT_SZ,
    )

    stable_secret_a = random_bytes(SECRET_SZ)
    session_secret_a = random_bytes(SECRET_SZ)
    stable_secret_b = random_bytes(SECRET_SZ)
    session_secret_b = random_bytes(SECRET_SZ)
    signature_a = random_bytes(SIGNATURE_SZ)
    signature_b = random_bytes(SIGNATURE_SZ)
    nonce_a = random_bytes(SESSION_NONCE_SZ)
    nonce_b = random_bytes(SESSION_NONCE_SZ)
    address_a = random_bytes(ADDRESS_SZ)
    address_b = random_bytes(ADDRESS_SZ)
    session_salt = random_bytes(SESSION_SALT_SZ)

    session_a = AloecryptSession.from_secrets(
        stable_secret_a,
        session_secret_a,
        signature_a,
        nonce_a,
        address_a,
        stable_secret_b,
        session_secret_b,
        signature_b,
        nonce_b,
        address_b,
        session_salt,
    )
    session_b = AloecryptSession.from_secrets(
        stable_secret_b,
        session_secret_b,
        signature_b,
        nonce_b,
        address_b,
        stable_secret_a,
        session_secret_a,
        signature_a,
        nonce_a,
        address_a,
        session_salt,
    )
    return session_a, session_b


def perform_handshake(
    session_a: SessionBuilder,
    session_b: SessionBuilder,
) -> None:
    """
    Full HELLO → SYN → ACK → SYNACK → WELCOME handshake.
    Mirrors: handshake.rs::perform_handshake
    """
    # A → B: HELLO
    intro_a = session_a.make_party_intro()
    session_b.on_counterparty_intro(intro_a)

    # B → A: SYN
    intro_b = session_b.make_party_intro()
    cipher_b = session_b.make_party_cipher()
    session_a.on_counterparty_intro(intro_b)
    session_a.on_counterparty_cipher(cipher_b)

    # A → B: ACK
    cipher_a = session_a.make_party_cipher()
    challenge_a = session_a.make_party_challenge()
    session_b.on_counterparty_cipher(cipher_a)
    session_b.on_counterparty_challenge(challenge_a)

    # B → A: SYNACK
    challenge_b = session_b.make_party_challenge()
    response_b = session_b.make_party_challenge_response()
    session_a.on_counterparty_challenge(challenge_b)
    session_a.on_counterparty_challenge_response(response_b)

    # A → B: WELCOME
    response_a = session_a.make_party_challenge_response()
    session_b.on_counterparty_challenge_response(response_a)


# ── custom_session.rs ─────────────────────────────────────────────────────────


class TestCustomSession:
    """Mirrors tests/custom_session.rs"""

    def test_bidirectional_messaging(self):
        """Mirrors: test_custom_session_bidirectional_messaging"""
        session_a, session_b = make_session_pair()

        plaintext_a = b"hello from custom session a"
        encrypted_a = session_a.encrypt(plaintext_a)
        decrypted_a = session_b.decrypt(encrypted_a)
        assert decrypted_a == plaintext_a, "A→B message mismatch"

        plaintext_b = b"hello back from custom session b"
        encrypted_b = session_b.encrypt(plaintext_b)
        decrypted_b = session_a.decrypt(encrypted_b)
        assert decrypted_b == plaintext_b, "B→A message mismatch"

    def test_wrong_secrets_fail_decryption(self):
        """Mirrors: test_custom_session_wrong_secrets_fail_decryption"""
        session_a, _ = make_session_pair()
        _, session_c = make_session_pair()  # completely independent secrets

        plaintext = b"this should not decrypt correctly"
        encrypted = session_a.encrypt(plaintext)

        with pytest.raises(Exception):
            session_c.decrypt(encrypted)

    def test_salt_is_significant(self):
        """Mirrors: test_custom_session_salt_is_significant"""
        from aloecrypt.consts import (
            SECRET_SZ,
            SIGNATURE_SZ,
            SESSION_NONCE_SZ,
            ADDRESS_SZ,
            SESSION_SALT_SZ,
        )

        stable_secret_a = random_bytes(SECRET_SZ)
        session_secret_a = random_bytes(SECRET_SZ)
        stable_secret_b = random_bytes(SECRET_SZ)
        session_secret_b = random_bytes(SECRET_SZ)
        signature_a = random_bytes(SIGNATURE_SZ)
        signature_b = random_bytes(SIGNATURE_SZ)
        nonce_a = random_bytes(SESSION_NONCE_SZ)
        nonce_b = random_bytes(SESSION_NONCE_SZ)
        address_a = random_bytes(ADDRESS_SZ)
        address_b = random_bytes(ADDRESS_SZ)

        salt_1 = bytearray(random_bytes(SESSION_SALT_SZ))
        salt_2 = bytearray(salt_1)
        salt_2[0] ^= 0xFF  # flip one byte

        shared_args = (
            stable_secret_a,
            session_secret_a,
            signature_a,
            nonce_a,
            address_a,
            stable_secret_b,
            session_secret_b,
            signature_b,
            nonce_b,
            address_b,
        )

        session_1 = AloecryptSession.from_secrets(*shared_args, bytes(salt_1))
        session_2 = AloecryptSession.from_secrets(*shared_args, bytes(salt_2))

        plaintext = b"same plaintext, different salt"
        ct1 = session_1.encrypt(plaintext)
        ct2 = session_2.encrypt(plaintext)

        assert ct1 != ct2, "Different salts should produce different ciphertexts"

    def test_empty_plaintext(self):
        """Mirrors: test_custom_session_empty_plaintext"""
        session_a, session_b = make_session_pair()

        plaintext = b""
        encrypted = session_a.encrypt(plaintext)
        decrypted = session_b.decrypt(encrypted)
        assert decrypted == plaintext

    def test_large_plaintext(self):
        """Mirrors: test_custom_session_large_plaintext"""
        session_a, session_b = make_session_pair()

        plaintext = bytes([0xAB] * 1024 * 1024)  # 1 MB
        encrypted = session_a.encrypt(plaintext)
        decrypted = session_b.decrypt(encrypted)
        assert decrypted == plaintext


# ── handshake.rs ──────────────────────────────────────────────────────────────


class TestHandshake:
    """Mirrors tests/handshake.rs"""

    def _make_builder_pair(self):
        signer_a = make_signer()
        signer_b = make_signer()
        delegate_a = signer_a.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        delegate_b = signer_b.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        address_a = signer_a.address
        address_b = signer_b.address
        session_a = SessionBuilder.create(address_b, delegate_a)
        session_b = SessionBuilder.create(address_a, delegate_b)
        return session_a, session_b

    def test_full_handshake_and_bidirectional_messaging(self):
        """Mirrors: test_full_handshake_and_bidirectional_messaging"""
        session_a, session_b = self._make_builder_pair()
        perform_handshake(session_a, session_b)

        built_a = session_a.build()
        built_b = session_b.build()

        plaintext_a = b"Hello from Party A!"
        encrypted_a = built_a.encrypt(plaintext_a)
        decrypted_a = built_b.decrypt(encrypted_a)
        assert decrypted_a == plaintext_a, "A→B message mismatch"

        plaintext_b = b"Hello back from Party B!"
        encrypted_b = built_b.encrypt(plaintext_b)
        decrypted_b = built_a.decrypt(encrypted_b)
        assert decrypted_b == plaintext_b, "B→A message mismatch"

    def test_intro_required_before_cipher(self):
        """Mirrors: test_handshake_intro_step_is_required_before_cipher"""
        session_a, session_b = self._make_builder_pair()

        # session_b has not received A's intro yet — cipher should fail
        with pytest.raises(Exception):
            session_b.make_party_cipher()

    def test_wrong_challenge_response_is_rejected(self):
        """Mirrors: test_wrong_challenge_response_is_rejected"""
        from aloecrypt.consts import SESSION_NONCE_SZ

        session_a, session_b = self._make_builder_pair()

        # Run up to the point where B expects A's challenge response
        intro_a = session_a.make_party_intro()
        session_b.on_counterparty_intro(intro_a)

        intro_b = session_b.make_party_intro()
        cipher_b = session_b.make_party_cipher()
        session_a.on_counterparty_intro(intro_b)
        session_a.on_counterparty_cipher(cipher_b)

        cipher_a = session_a.make_party_cipher()
        challenge_a = session_a.make_party_challenge()
        session_b.on_counterparty_cipher(cipher_a)
        session_b.on_counterparty_challenge(challenge_a)

        challenge_b = session_b.make_party_challenge()
        response_b = session_b.make_party_challenge_response()
        session_a.on_counterparty_challenge(challenge_b)
        session_a.on_counterparty_challenge_response(response_b)

        # Send a fabricated all-zeros response instead of the real one
        fake_response = PartyRESPONSE(decrypted_challenge=bytes(SESSION_NONCE_SZ))
        with pytest.raises(Exception):
            session_b.on_counterparty_challenge_response(fake_response)


# ── pem.rs ────────────────────────────────────────────────────────────────────


class TestPEM:
    """Mirrors tests/pem.rs"""

    def test_load_and_unload_pem(self):
        """Mirrors: load_and_unload_pem"""
        password = b"Test Password!"
        salt = b"Test Salt!"

        signer = DilithiumSigner.new()
        signer_pem = signer.to_x_pem(password, salt)
        loaded_signer = DilithiumSigner.from_x_pem(signer_pem, password, salt)

        verifier = loaded_signer.to_verifier()
        verifier_pem = verifier.to_pem()
        loaded_verifier = DilithiumVerifier.from_pem(verifier_pem)

        kyber = KyberFullKEM.create(
            loaded_signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0
        )
        kyber_pem = kyber.to_x_pem(password, salt)
        loaded_kyber = KyberFullKEM.from_x_pem(kyber_pem, password, salt)

        kyber_pub = loaded_kyber.to_public()
        kyber_pub_pem = kyber_pub.to_pem()
        _loaded_kyber_pub = KyberPublicKEM.from_pem(kyber_pub_pem)

    def test_verify_loaded_pem(self):
        """Mirrors: verify_loaded_pem"""
        password = b"Test Password!"
        salt = b"Test Salt!"

        signer = DilithiumSigner.new()
        signer_pem = signer.to_x_pem(password, salt)
        loaded_signer = DilithiumSigner.from_x_pem(signer_pem, password, salt)

        verifier = loaded_signer.to_verifier()
        verifier_pem = verifier.to_pem()
        loaded_verifier = DilithiumVerifier.from_pem(verifier_pem)

        kyber = KyberFullKEM.create(
            loaded_signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0
        )
        kyber_pem = kyber.to_x_pem(password, salt)
        loaded_kyber = KyberFullKEM.from_x_pem(kyber_pem, password, salt)
        kyber_pub = loaded_kyber.to_public()
        kyber_pub_pem = kyber_pub.to_pem()
        loaded_kyber_pub = KyberPublicKEM.from_pem(kyber_pub_pem)
        
        sig_verify_result = verifier.verify(loaded_verifier.signing_material(), loaded_verifier.dlt_sig_bytes )
        print("verifier pubkey == loaded_verifier pubkey:", verifier.dlt_pubkey == loaded_verifier.dlt_pubkey)
        print("signing_material match:", verifier.signing_material() == loaded_verifier.signing_material())
        print("sig len before PEM:", len(verifier.dlt_sig_bytes))
        print("sig len after PEM:", len(loaded_verifier.dlt_sig_bytes))
        print("sig bytes match:", verifier.dlt_sig_bytes == loaded_verifier.dlt_sig_bytes)
        print(f"       verifier.dlt_sig_bytes: {verifier.dlt_sig_bytes.hex()[0:10]}")
        print(f"loaded_verifier.dlt_sig_bytes: {loaded_verifier.dlt_sig_bytes.hex()[0:10]}")
        print(f"            sig_verify_result: {sig_verify_result}")

        
        assert verifier.verify(
            loaded_verifier.signing_material(), loaded_verifier.dlt_sig_bytes
        )
        assert loaded_verifier.verify(signer.signing_material(), signer.dlt_sig_bytes)
        assert loaded_verifier.verify(
            verifier.signing_material(), verifier.dlt_sig_bytes
        )
        assert loaded_verifier.verify(
            loaded_verifier.signing_material(), loaded_verifier.dlt_sig_bytes
        )
        assert loaded_verifier.verify(kyber.signing_material(), kyber.kyb_sig_bytes)
        assert loaded_verifier.verify(
            kyber_pub.signing_material(), kyber_pub.kyb_sig_bytes
        )
        assert loaded_verifier.verify(
            loaded_kyber.signing_material(), loaded_kyber.kyb_sig_bytes
        )
        assert loaded_verifier.verify(
            loaded_kyber_pub.signing_material(), loaded_kyber_pub.kyb_sig_bytes
        )


# ── pqc.rs ────────────────────────────────────────────────────────────────────


class TestPQC:
    """Mirrors tests/pqc.rs"""

    def test_instantiate_and_verify_signatures(self):
        """Mirrors: instantiate_and_verify_signatures"""
        signer = DilithiumSigner.new()
        verifier = signer.to_verifier()

        kyber_full = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        kyber_public = kyber_full.to_public()

        assert verifier.verify(signer.signing_material(), signer.dlt_sig_bytes), (
            "Signer self-signature verification failed"
        )
        assert verifier.verify(
            kyber_full.signing_material(), kyber_full.kyb_sig_bytes
        ), "KyberFullKEM signature verification failed"
        assert verifier.verify(
            kyber_public.signing_material(), kyber_public.kyb_sig_bytes
        ), "KyberPublicKEM signature verification failed"

    def test_sign_and_verify(self):
        """Mirrors: sign_and_verify"""
        root_signer = DilithiumSigner.new()
        root_verifier = root_signer.to_verifier()

        msg = b"Hello world this is a longer message. It was the best of times, it was the... blurst of times?!"
        signature = root_signer.sign(msg)
        root_verifier.verify(msg, signature)

        derivative = root_signer.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

        assert not derivative.is_root()
        assert derivative.address == root_signer.address
        assert derivative.dlt_pubkey != root_signer.dlt_pubkey
        assert derivative.dlt_privkey != root_signer.dlt_privkey

        # Root verifier should successfully verify the derivative's signing material
        assert root_verifier.verify(
            derivative.signing_material(), derivative.dlt_sig_bytes
        ), "Root verifier failed to verify derivative"

        # Derivative should NOT be able to verify its own signing material
        assert not derivative.to_verifier().verify(
            derivative.signing_material(), derivative.dlt_sig_bytes
        ), "Derivative should not self-verify"

    def test_encapsulate_and_decapsulate(self):
        """Encapsulate with public key, decapsulate with full key, secrets match."""
        signer = DilithiumSigner.new()
        kyber_full = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        kyber_pub = kyber_full.to_public()

        ciphertext, shared_secret = kyber_pub.encapsulate()
        recovered = kyber_full.decapsulate(ciphertext)

        assert len(ciphertext) == 1088
        assert len(shared_secret) == 32
        assert recovered == shared_secret


class TestKEM:
    """Direct encapsulate/decapsulate coverage."""

    def test_encapsulate_returns_correct_sizes(self):
        signer = DilithiumSigner.new()
        full_kem = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        pub_kem = full_kem.to_public()

        ciphertext, shared_secret = pub_kem.encapsulate()

        assert len(ciphertext) == 1088, (
            f"Expected 1088-byte ciphertext, got {len(ciphertext)}"
        )
        assert len(shared_secret) == 32, (
            f"Expected 32-byte secret, got {len(shared_secret)}"
        )

    def test_decapsulate_recovers_shared_secret(self):
        signer = DilithiumSigner.new()
        full_kem = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        pub_kem = full_kem.to_public()

        ciphertext, sent_secret = pub_kem.encapsulate()
        recv_secret = full_kem.decapsulate(ciphertext)

        assert sent_secret == recv_secret, (
            "Encapsulated and decapsulated secrets do not match"
        )

    def test_different_encapsulations_produce_different_secrets(self):
        signer = DilithiumSigner.new()
        full_kem = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        pub_kem = full_kem.to_public()

        ct1, secret1 = pub_kem.encapsulate()
        ct2, secret2 = pub_kem.encapsulate()

        assert ct1 != ct2, "Two encapsulations should produce different ciphertexts"
        assert secret1 != secret2, "Two encapsulations should produce different secrets"

    def test_wrong_key_cannot_decapsulate(self):
        signer_a = DilithiumSigner.new()
        signer_b = DilithiumSigner.new()
        kem_a = KyberFullKEM.create(signer_a, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        kem_b = KyberFullKEM.create(signer_b, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

        ciphertext, sent_secret = kem_a.to_public().encapsulate()

        # B decapsulating A's ciphertext should either fail or return a different secret
        try:
            wrong_secret = kem_b.decapsulate(ciphertext)
            assert wrong_secret != sent_secret, (
                "Wrong key should not recover the correct shared secret"
            )
        except Exception:
            pass  # failing is also acceptable

    def test_decapsulate_rejects_wrong_size_ciphertext(self):
        signer = DilithiumSigner.new()
        full_kem = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

        with pytest.raises(Exception):
            full_kem.decapsulate(b"tooshort")

    def test_canonical_kem_round_trip(self):
        """Canonical KEM derived from same signer+index produces same public key."""
        signer = DilithiumSigner.new()

        kem1 = KyberFullKEM.canonical(
            signer, b"\x00", EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0
        )
        kem2 = KyberFullKEM.canonical(
            signer, b"\x00", EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0
        )

        assert kem1.kyb_pubkey == kem2.kyb_pubkey, (
            "Canonical KEM with same inputs should produce the same public key"
        )

    def test_canonical_kem_different_index(self):
        """Different indices produce different keypairs."""
        signer = DilithiumSigner.new()

        kem0 = KyberFullKEM.canonical(
            signer, b"\x00", EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0
        )
        kem1 = KyberFullKEM.canonical(
            signer, b"\x01", EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0
        )

        assert kem0.kyb_pubkey != kem1.kyb_pubkey, (
            "Different indices should produce different public keys"
        )

    def test_pem_round_trip_preserves_decapsulation(self):
        """A full KEM saved and reloaded should decapsulate correctly."""
        password = b"test-password"
        salt = b"test-salt"
        signer = DilithiumSigner.new()
        full_kem = KyberFullKEM.create(signer, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
        pub_kem = full_kem.to_public()

        ciphertext, sent_secret = pub_kem.encapsulate()

        pem = full_kem.to_x_pem(password, salt)
        loaded_kem = KyberFullKEM.from_x_pem(pem, password, salt)
        recv_secret = loaded_kem.decapsulate(ciphertext)

        assert recv_secret == sent_secret, (
            "Reloaded KEM should decapsulate to the same shared secret"
        )


# Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
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
