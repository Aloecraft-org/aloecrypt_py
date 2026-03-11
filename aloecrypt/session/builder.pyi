# ./aloecrypt/session/builder.pyi
# License: Apache-2.0 (disclaimer at bottom of file)
# Generated - Do Not Modify
# file: aloecrypt/session/builder.pyi

from typing import Optional
from aloecrypt.signatory import DilithiumSigner, DilithiumVerifier
from aloecrypt.kem import KyberFullKEM, KyberPublicKEM

class FullCIPHER:
    stable_cipher: bytes
    session_cipher: bytes
    stable_secret: bytes
    session_secret: bytes
    signature: bytes

class PartyCHALLENGE:
    encrypted_challenge: bytes
    encrypted_check: bytes

class PartyCIPHER:
    stable_cipher: bytes
    session_cipher: bytes
    signature: bytes

class PartyChallenge:
    encrypted_challenge: bytes
    encrypted_check: bytes
    decrypted_challenge: bytes
    decrypted_check: bytes

class PartyINTRO:
    address: bytes
    nonce: bytes
    stable_kem: KyberPublicKEM
    session_kem: KyberPublicKEM
    verifier: DilithiumVerifier

class PartyRESPONSE:
    decrypted_challenge: bytes

class PartySecret:
    stable_secret: bytes
    session_secret: bytes
    signature: bytes

class SessionBuilder:
    """Constructs an [AloecryptSession][] through a five-message handshake.

        The handshake establishes mutual authentication and a shared double-KEM
        secret between two parties. Neither party can build a session until both
        have proven they can decrypt each other's ciphertext.

        Handshake sequence:
    ```
        A                          B
        |-- HELLO (make_intro) --->|
        |<-- SYN (intro+cipher) ---|
        |-- ACK (cipher+challenge)->|
        |<-- SYNACK (challenge+response) --|
        |-- WELCOME (response) --->|
        |         build()          |         build()
    ```

        Example:
    ```python
            signer_a = DilithiumSigner.new()
            delegate_a = signer_a.create_delegate(b'\\x00'*8, b'\\x00'*8, 0, 0)
            session_a = SessionBuilder.create(address_b, delegate_a)

            signer_b = DilithiumSigner.new()
            delegate_b = signer_b.create_delegate(b'\\x00'*8, b'\\x00'*8, 0, 0)
            session_b = SessionBuilder.create(address_a, delegate_b)

            # HELLO
            intro_a = session_a.make_party_intro()
            session_b.on_counterparty_intro(intro_a)

            # SYN
            session_a.on_counterparty_intro(session_b.make_party_intro())
            session_a.on_counterparty_cipher(session_b.make_party_cipher())

            # ACK
            session_b.on_counterparty_cipher(session_a.make_party_cipher())
            session_b.on_counterparty_challenge(session_a.make_party_challenge())

            # SYNACK
            session_a.on_counterparty_challenge(session_b.make_party_challenge())
            session_a.on_counterparty_challenge_response(session_b.make_party_challenge_response())

            # WELCOME
            session_b.on_counterparty_challenge_response(session_a.make_party_challenge_response())

            built_a = session_a.build()
            built_b = session_b.build()
    ```
    """

    delegate_signer: DilithiumSigner
    """The delegate ML-DSA signer used to sign this party's KEM material."""
    stable_kem: KyberFullKEM
    """Long-lived ML-KEM keypair tied to this party's root identity."""
    session_kem: KyberFullKEM
    """Ephemeral ML-KEM keypair generated fresh for this session."""
    nonce: bytes
    """Random nonce included in the intro, used in session salt derivation."""
    challenge_nonce: bytes
    """Random nonce encrypted as the proof-of-decryption challenge."""
    session_salt: Optional[bytes]
    """Derived once both ciphers have been exchanged. None until that point."""
    signature: Optional[bytes]
    """This party's ML-DSA signature over the handshake material."""
    cipher: Optional[FullCIPHER]
    """This party's encapsulated stable and session ciphertexts."""
    counterparty_intro: Optional[PartyINTRO]
    """The counterparty's intro, populated by on_counterparty_intro."""
    counterparty_cipher: Optional[PartySecret]
    """The decapsulated counterparty secrets, populated by on_counterparty_cipher."""
    counterparty_challenge: Optional[PartyChallenge]
    """The counterparty's challenge, populated by on_counterparty_challenge."""
    build_ready: bool
    """True once the full handshake has completed and build() may be called."""

    @classmethod
    def create(
        cls, counterparty_address: bytes, delegate_signer: DilithiumSigner
    ) -> SessionBuilder:
        """Create a new SessionBuilder targeting a specific counterparty.

        Args:
            counterparty_address: The 32-byte address of the intended peer.
                Used to bind the session to a specific identity.
            delegate_signer: A delegate ML-DSA signer derived from your root
                identity. Must not be the root signer itself.

        Returns:
            A fresh SessionBuilder ready to begin the handshake.
        """
        ...

    @property
    def address(self) -> bytes:
        """This party's 32-byte address, derived from the delegate signer."""
        ...

    def make_party_intro(self) -> PartyINTRO:
        """Produce this party's intro message (HELLO / SYN step).

        The intro contains the party's address, nonce, stable and session
        public KEM keys, and ML-DSA verifier. Send this to the counterparty
        before exchanging ciphers.

        Returns:
            A PartyINTRO to transmit to the counterparty.
        """
        ...

    def on_counterparty_intro(self, intro: PartyINTRO) -> SessionBuilder:
        """Ingest the counterparty's intro message.

        Must be called before make_party_cipher. Stores the counterparty's
        public keys and verifier for use in subsequent steps.

        Args:
            intro: The PartyINTRO received from the counterparty.

        Returns:
            Self, with counterparty intro state populated.

        Raises:
            Exception: If the intro is malformed or the signature is invalid.
        """
        ...

    def make_party_cipher(self) -> PartyCIPHER:
        """Encapsulate secrets against the counterparty's public KEM keys (ACK / SYN step).

        Encapsulates one secret against the counterparty's stable key and one
        against their session key. Requires on_counterparty_intro to have been
        called first.

        Returns:
            A PartyCIPHER containing the two ciphertexts and a signature.

        Raises:
            Exception: If called before on_counterparty_intro.
        """
        ...

    def on_counterparty_cipher(self, cipher: PartyCIPHER) -> SessionBuilder:
        """Decapsulate the counterparty's cipher and derive the session salt.

        Decapsulates both KEM ciphertexts using this party's private keys,
        then combines all four secrets to derive the shared session salt.

        Args:
            cipher: The PartyCIPHER received from the counterparty.

        Returns:
            Self, with session salt derived and counterparty secrets stored.

        Raises:
            Exception: If decapsulation fails or the signature does not verify.
        """
        ...

    def make_party_challenge(self) -> PartyCHALLENGE:
        """Encrypt a random challenge nonce for the counterparty (ACK / SYNACK step).

        The counterparty must decrypt this and return the plaintext as proof
        they hold the session keys. Requires the session salt to be derived
        (i.e. on_counterparty_cipher must have been called).

        Returns:
            A PartyCHALLENGE containing the encrypted challenge and check value.
        """
        ...

    def on_counterparty_challenge(self, challenge: PartyCHALLENGE) -> SessionBuilder:
        """Decrypt and store the counterparty's challenge (SYNACK / WELCOME step).

        Args:
            challenge: The PartyCHALLENGE received from the counterparty.

        Returns:
            Self, with the decrypted challenge stored for response generation.

        Raises:
            Exception: If decryption of the challenge fails.
        """
        ...

    def make_party_challenge_response(self) -> PartyRESPONSE:
        """Produce the plaintext challenge response (SYNACK / WELCOME step).

        Returns the decrypted challenge nonce to prove this party can decrypt
        using the derived session keys.

        Returns:
            A PartyRESPONSE containing the decrypted challenge nonce.
        """
        ...

    def on_counterparty_challenge_response(
        self, response: PartyRESPONSE
    ) -> SessionBuilder:
        """Verify the counterparty's challenge response and mark the handshake complete.

        Confirms the counterparty returned the correct plaintext, proving
        mutual proof-of-decryption. Sets build_ready to True on success.

        Args:
            response: The PartyRESPONSE received from the counterparty.

        Returns:
            Self, with build_ready set to True.

        Raises:
            Exception: If the response does not match the original challenge.
        """
        ...

    def build(self) -> AloecryptSession:
        """Finalise the handshake and return a ready-to-use session.

        Returns:
            An AloecryptSession with symmetric encrypt/decrypt available.

        Raises:
            Exception: If the handshake is not yet complete (build_ready is False).
        """
        ...

from aloecrypt.session import AloecryptSession
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
