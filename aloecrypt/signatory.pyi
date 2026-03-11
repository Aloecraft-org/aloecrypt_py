# ./aloecrypt/signatory.pyi
# License: Apache-2.0 (disclaimer at bottom of file)
# file: aloecrypt/signatory.pyi

class DilithiumSigner:
    """An ML-DSA-65 signing keypair with an embedded identity chain.

        The root signer is the anchor of an identity. Delegates are derived from
        it with a constrained lifetime and refresh budget. All KEM keys and
        session material are signed by a delegate, never the root directly.

        The address is stable across delegates — all delegates derived from the
        same root share the same address, allowing peers to recognise the identity
        regardless of which delegate is currently active.

        Example:
    ```python
            from aloecrypt import DilithiumSigner
            from aloecrypt.consts import EMPTY_TIMESTAMP

            # Create a root identity
            root = DilithiumSigner.new()

            # Derive a delegate for active use
            delegate = root.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

            # Persist the root securely
            pem = root.to_x_pem(b"password", b"salt")
            loaded = DilithiumSigner.from_x_pem(pem, b"password", b"salt")
    ```
    """

    dlt_pubkey: bytes
    """ML-DSA-65 public key (1952 bytes)."""
    dlt_privkey: bytes
    """ML-DSA-65 private key (4032 bytes)."""
    dlt_sig_bytes: bytes
    """Signature over this key's signing material, produced by its parent."""
    dlt_address: bytes
    """32-byte identity address. Stable across all delegates from the same root."""
    dlt_auth_id: bytes
    """32-byte auth ID of the parent that signed this key. Equal to dlt_address on root signers."""
    dlt_created_at: bytes
    """8-byte timestamp of when this key was created."""
    dlt_active_from: bytes
    """8-byte timestamp from which this key is considered valid."""
    dlt_expires_at: bytes
    """8-byte timestamp after which this key is no longer valid."""
    dlt_refresh_count: int
    """Number of times this delegate has been refreshed."""
    dlt_max_refresh: int
    """Maximum number of refreshes permitted for this delegate."""

    @classmethod
    def new(cls) -> DilithiumSigner:
        """Generate a new root ML-DSA-65 signing keypair.

        The resulting signer is a root identity — it is self-signed and has
        no parent. Use create_delegate before passing to SessionBuilder or
        KyberFullKEM.create.

        Returns:
            A freshly generated root DilithiumSigner.
        """
        ...

    @classmethod
    def from_x_pem(cls, pem: str, password: bytes, salt: bytes) -> DilithiumSigner:
        """Load a signer from an encrypted PEM string.

        Args:
            pem: The encrypted PEM string produced by to_x_pem.
            password: The password used when the PEM was created.
            salt: The salt used when the PEM was created.

        Returns:
            The recovered DilithiumSigner.

        Raises:
            Exception: If decryption fails or the PEM is malformed.
        """
        ...

    def to_verifier(self) -> DilithiumVerifier:
        """Strip the private key and return the public verifier.

        Returns:
            A DilithiumVerifier containing only the public key and metadata.
        """
        ...

    @property
    def address(self) -> bytes:
        """32-byte identity address, shared across all delegates from this root."""
        ...

    @property
    def auth_id(self) -> bytes:
        """32-byte auth ID of the key that signed this signer."""
        ...

    def is_root(self) -> bool:
        """Return True if this is a root signer (self-signed, no parent)."""
        ...

    def is_time_active(self) -> bool:
        """Return True if the current time falls within active_from and expires_at."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Produce an ML-DSA-65 signature over arbitrary bytes.

        Args:
            message: The bytes to sign.

        Returns:
            A 3309-byte ML-DSA-65 signature.
        """
        ...

    def sign_hex(self, message: bytes) -> str:
        """Produce an ML-DSA-65 signature and return it as a hex string.

        Args:
            message: The bytes to sign.

        Returns:
            The signature encoded as a lowercase hex string.
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

    def create_delegate(
        self,
        active_from: bytes,
        expires_at: bytes,
        refresh_count: int,
        max_refresh: int,
    ) -> DilithiumSigner:
        """Derive a delegate signer from this root identity.

        The delegate shares the same address as the root but has its own
        keypair, signed by the root. Pass the delegate — not the root — to
        SessionBuilder and KyberFullKEM.

        Args:
            active_from: 8-byte timestamp from which the delegate is valid.
                Pass EMPTY_TIMESTAMP for no lower bound.
            expires_at: 8-byte timestamp after which the delegate expires.
                Pass EMPTY_TIMESTAMP for no expiry.
            refresh_count: Current refresh count, typically 0 for a new delegate.
            max_refresh: Maximum number of times this delegate may be refreshed.
                Pass 0 for unlimited.

        Returns:
            A new DilithiumSigner delegate signed by this root.
        """
        ...

    def signing_material(self) -> bytes:
        """Return the canonical bytes that should be signed to authenticate this key.

        Returns:
            The signing material as bytes.
        """
        ...

    def signing_auth_id(self) -> bytes:
        """Return the auth ID that a verifier of this key's signatures would carry.

        Returns:
            32-byte auth ID bytes.
        """
        ...

class DilithiumVerifier:
    """The public half of a DilithiumSigner — verifies signatures and PEM serialisation.

        Obtained by calling to_verifier on a signer, or loaded from a PEM string.
        Safe to share publicly; contains no private key material.

        Example:
    ```python
            verifier = signer.to_verifier()
            pem = verifier.to_pem()

            # Share pem with peers
            loaded = DilithiumVerifier.from_pem(pem)
            assert loaded.verify(signer.signing_material(), signer.dlt_sig_bytes)
    ```
    """

    dlt_pubkey: bytes
    """ML-DSA-65 public key (1952 bytes)."""
    dlt_sig_bytes: bytes
    """Signature over this key's signing material, produced by its parent."""
    dlt_address: bytes
    """32-byte identity address."""
    dlt_auth_id: bytes
    """32-byte auth ID of the parent that signed this key."""
    dlt_created_at: bytes
    """8-byte creation timestamp."""
    dlt_active_from: bytes
    """8-byte timestamp from which this key is valid."""
    dlt_expires_at: bytes
    """8-byte expiry timestamp."""
    dlt_refresh_count: int
    """Number of times the corresponding delegate has been refreshed."""
    dlt_max_refresh: int
    """Maximum refreshes permitted."""

    @classmethod
    def from_pem(cls, pem: str) -> DilithiumVerifier:
        """Load a verifier from an unencrypted PEM string.

        Args:
            pem: A PEM string produced by to_pem.

        Returns:
            The recovered DilithiumVerifier.

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
        """32-byte auth ID of the key that signed this verifier."""
        ...

    def verify(self, material: bytes, sig_bytes: bytes) -> bool:
        """Verify an ML-DSA-65 signature.

        Args:
            material: The bytes that were signed.
            sig_bytes: The 3309-byte signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        ...

    def is_root(self) -> bool:
        """Return True if this verifier corresponds to a root signer."""
        ...

    def is_time_active(self) -> bool:
        """Return True if the current time falls within active_from and expires_at."""
        ...

    def to_pem(self) -> str:
        """Serialise the public key to an unencrypted PEM string.

        Returns:
            A PEM string containing only public key material.
        """
        ...

    def signing_material(self) -> bytes:
        """Return the canonical bytes used to verify this key's own signature.

        Returns:
            The signing material as bytes.
        """
        ...

    def signing_auth_id(self) -> bytes:
        """Return the auth ID that a verifier of this key's signatures would carry.

        Returns:
            32-byte auth ID bytes.
        """
        ...

class XDilithiumSigner:
    dlt_pubkey: bytes
    x_dlt_privkey: bytes
    dlt_sig_bytes: bytes
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
