# ./aloecrypt/kem.pyi
# License: Apache-2.0 (disclaimer at bottom of file)
# file: aloecrypt/kem.pyi

from aloecrypt.signatory import DilithiumSigner

class KyberFullKEM:
    """An ML-KEM-768 keypair bound to a Dilithium identity.

        Holds both the encapsulation (public) and decapsulation (private) keys,
        signed by a delegate DilithiumSigner. Used internally by SessionBuilder
        as either the stable or ephemeral session KEM.

        Two construction modes are available. Use create for a randomly generated
        keypair. Use canonical when you need a deterministic keypair derived from
        the signer and an index — useful for stable long-lived KEMs that must be
        reproducible from the root identity.

        Example:
    ```python
            from aloecrypt import DilithiumSigner, KyberFullKEM
            from aloecrypt.consts import EMPTY_TIMESTAMP

            root = DilithiumSigner.new()
            delegate = root.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

            # Random keypair
            kem = KyberFullKEM.create(delegate, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

            # Deterministic keypair at index 0
            stable_kem = KyberFullKEM.canonical(delegate, b'\\x00', EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

            # Share the public half with peers
            public_kem = kem.to_public()
            pem = public_kem.to_pem()
    ```
    """

    kyb_pubkey: bytes
    """ML-KEM-768 encapsulation (public) key (1184 bytes)."""
    kyb_privkey: bytes
    """ML-KEM-768 decapsulation (private) key (2400 bytes)."""
    kyb_sig_bytes: bytes
    """ML-DSA-65 signature over this key's signing material."""
    dlt_address: bytes
    """32-byte identity address inherited from the signing delegate."""
    dlt_auth_id: bytes
    """32-byte auth ID of the delegate that signed this key."""
    dlt_created_at: bytes
    """8-byte creation timestamp."""
    dlt_active_from: bytes
    """8-byte timestamp from which this key is valid."""
    dlt_expires_at: bytes
    """8-byte expiry timestamp."""
    dlt_refresh_count: int
    """Current refresh count."""
    dlt_max_refresh: int
    """Maximum refreshes permitted."""

    @classmethod
    def create(
        cls,
        signer: DilithiumSigner,
        active_from: bytes,
        expires_at: bytes,
        refresh_count: int,
        max_refresh: int,
    ) -> KyberFullKEM:
        """Generate a random ML-KEM-768 keypair signed by the given delegate.

        Args:
            signer: A delegate DilithiumSigner. Must not be a root signer.
            active_from: 8-byte timestamp from which the key is valid.
                Pass EMPTY_TIMESTAMP for no lower bound.
            expires_at: 8-byte expiry timestamp.
                Pass EMPTY_TIMESTAMP for no expiry.
            refresh_count: Current refresh count, typically 0.
            max_refresh: Maximum number of refreshes permitted. Pass 0 for unlimited.

        Returns:
            A freshly generated KyberFullKEM signed by the delegate.
        """
        ...

    @classmethod
    def canonical(
        cls,
        signer: DilithiumSigner,
        idx: bytes,
        active_from: bytes,
        expires_at: bytes,
        refresh_count: int,
        max_refresh: int,
    ) -> KyberFullKEM:
        """Derive a deterministic ML-KEM-768 keypair from the signer and an index.

        The keypair is derived via HKDF from the signer's key material and
        the index, so the same inputs always produce the same keypair. Use
        this for stable KEMs that must survive serialisation and reload
        without storing the private key separately.

        Args:
            signer: A delegate DilithiumSigner.
            idx: An arbitrary byte index distinguishing this keypair from
                others derived from the same signer. Typically b'\\x00' for
                the first stable KEM.
            active_from: 8-byte validity start timestamp.
            expires_at: 8-byte expiry timestamp.
            refresh_count: Current refresh count.
            max_refresh: Maximum refreshes permitted.

        Returns:
            A deterministically derived KyberFullKEM signed by the delegate.
        """
        ...

    @classmethod
    def from_x_pem(cls, pem: str, password: bytes, salt: bytes) -> KyberFullKEM:
        """Load a full keypair from an encrypted PEM string.

        Args:
            pem: An encrypted PEM string produced by to_x_pem.
            password: The password used when the PEM was created.
            salt: The salt used when the PEM was created.

        Returns:
            The recovered KyberFullKEM.

        Raises:
            Exception: If decryption fails or the PEM is malformed.
        """
        ...

    @property
    def address(self) -> bytes:
        """32-byte identity address inherited from the signing delegate."""
        ...

    @property
    def auth_id(self) -> bytes:
        """32-byte auth ID of the delegate that signed this key."""
        ...

    def to_public(self) -> KyberPublicKEM:
        """Strip the private key and return the public half.

        Returns:
            A KyberPublicKEM safe to share with peers.
        """
        ...

    def to_x_pem(self, password: bytes, salt: bytes) -> str:
        """Serialise the full keypair to an encrypted PEM string.

        The private key is encrypted with ChaCha20-Poly1305 using a key
        derived from password and salt via PBKDF2.

        Args:
            password: Encryption password.
            salt: Encryption salt. Use a unique value per keypair.

        Returns:
            An encrypted PEM string safe for storage.
        """
        ...

    def signing_material(self) -> bytes:
        """Return the canonical bytes used to verify this key's signature.

        Returns:
            The signing material as bytes.
        """
        ...

class KyberPublicKEM:
    """The public half of a KyberFullKEM — encapsulation key only.

        Contains only the ML-KEM-768 encapsulation key and identity metadata.
        Safe to share with peers. Peers use this to encapsulate a shared secret
        that only the holder of the corresponding KyberFullKEM can decapsulate.

        Obtained via KyberFullKEM.to_public, or loaded from a PEM string shared
        out-of-band.

        Example:
    ```python
            # Recipient shares their public KEM
            pem = full_kem.to_public().to_pem()

            # Sender loads it and includes it in a PartyINTRO
            public_kem = KyberPublicKEM.from_pem(pem)
    ```
    """

    kyb_pubkey: bytes
    """ML-KEM-768 encapsulation key (1184 bytes)."""
    kyb_sig_bytes: bytes
    """ML-DSA-65 signature over this key's signing material."""
    dlt_address: bytes
    """32-byte identity address."""
    dlt_auth_id: bytes
    """32-byte auth ID of the delegate that signed this key."""
    dlt_created_at: bytes
    """8-byte creation timestamp."""
    dlt_active_from: bytes
    """8-byte validity start timestamp."""
    dlt_expires_at: bytes
    """8-byte expiry timestamp."""
    dlt_refresh_count: int
    """Current refresh count."""
    dlt_max_refresh: int
    """Maximum refreshes permitted."""

    @classmethod
    def from_pem(cls, pem: str) -> KyberPublicKEM:
        """Load a public KEM from an unencrypted PEM string.

        Args:
            pem: A PEM string produced by to_pem.

        Returns:
            The recovered KyberPublicKEM.

        Raises:
            Exception: If the PEM is malformed.
        """
        ...

    @property
    def address(self) -> bytes:
        """32-byte identity address."""
        ...

    @property
    def auth_id(self) -> bytes:
        """32-byte auth ID of the delegate that signed this key."""
        ...

    def to_pem(self) -> str:
        """Serialise the public key to an unencrypted PEM string.

        Returns:
            A PEM string containing only public key material, safe to share.
        """
        ...

    def signing_material(self) -> bytes:
        """Return the canonical bytes used to verify this key's signature.

        Returns:
            The signing material as bytes.
        """
        ...

class XKyberFullKEM:
    kyb_pubkey: bytes
    x_kyb_privkey: bytes
    kyb_sig_bytes: bytes
    dlt_address: bytes
    dlt_auth_id: bytes
    dlt_created_at: bytes
    dlt_active_from: bytes
    dlt_expires_at: bytes
    dlt_refresh_count: int
    dlt_max_refresh: int
    nonce: bytes

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
