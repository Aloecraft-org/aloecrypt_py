# ./aloecrypt/session/__init__.pyi
# License: Apache-2.0 (disclaimer at bottom of file)
# file: aloecrypt/session/__init__.pyi

from aloecrypt.session import AloecryptSession as AloecryptSession

# ── AloecryptSession ─────────────────────────────────────────────────────────
class AloecryptSession:
    """An established post-quantum encrypted session between two parties.

        Obtained either by completing a [SessionBuilder][] handshake or by
        constructing directly from pre-shared secrets via
        [from_secrets][aloecrypt.session.AloecryptSession.from_secrets].

        Each message is encrypted with ChaCha20-Poly1305 using a double-KEM
        derived key — one layer from the stable keypair, one from the ephemeral
        session keypair. Nonces are derived deterministically from the session
        salt and a per-message counter, eliminating nonce reuse.

        Example:
    ```python
            # Via handshake (typical)
            built_a, built_b = perform_handshake(session_a, session_b)

            ciphertext = built_a.encrypt(b"hello")
            plaintext  = built_b.decrypt(ciphertext)

            # Via pre-shared secrets (custom / out-of-band sessions)
            session = AloecryptSession.from_secrets(
                stable_secret_a, session_secret_a, signature_a, nonce_a, address_a,
                stable_secret_b, session_secret_b, signature_b, nonce_b, address_b,
                session_salt,
            )
    ```
    """

    @classmethod
    def from_secrets(
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
        """Construct a session directly from pre-shared KEM secrets.

        Useful when the two parties have established secrets through a custom
        or out-of-band protocol rather than the standard handshake. Party A
        and Party B must call this with their roles swapped — A passes its
        own secrets first, B passes its own secrets first.

        Args:
            stable_secret_a: 32-byte decapsulated secret from party A's stable KEM.
            session_secret_a: 32-byte decapsulated secret from party A's session KEM.
            signature_a: Party A's ML-DSA signature over the handshake material.
            nonce_a: Party A's 32-byte session nonce.
            address_a: Party A's 32-byte identity address.
            stable_secret_b: 32-byte decapsulated secret from party B's stable KEM.
            session_secret_b: 32-byte decapsulated secret from party B's session KEM.
            signature_b: Party B's ML-DSA signature over the handshake material.
            nonce_b: Party B's 32-byte session nonce.
            address_b: Party B's 32-byte identity address.
            session_salt: 32-byte shared salt used in key derivation. Must be
                identical on both sides.

        Returns:
            A fully constructed AloecryptSession ready for encrypt/decrypt.
        """
        ...

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a message for the counterparty.

        Args:
            plaintext: The raw bytes to encrypt. May be empty.

        Returns:
            The ciphertext, including the authentication tag and nonce prefix.
        """
        ...

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a message received from the counterparty.

        Args:
            ciphertext: The ciphertext produced by the counterparty's encrypt call.

        Returns:
            The recovered plaintext bytes.

        Raises:
            Exception: If authentication fails or the ciphertext is malformed.
        """
        ...  # Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>

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
