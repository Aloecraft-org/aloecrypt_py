# ./aloecrypt/__init__.pyi
# License: Apache-2.0 (disclaimer at bottom of file)
# Not generated - this file maps the public API of the aloecrypt package
# file: aloecrypt/__init__.pyi

from aloecrypt.signatory import DilithiumSigner as DilithiumSigner
from aloecrypt.signatory import DilithiumVerifier as DilithiumVerifier
from aloecrypt.kem import KyberFullKEM as KyberFullKEM
from aloecrypt.kem import KyberPublicKEM as KyberPublicKEM
from aloecrypt.session.builder import FullCIPHER as FullCIPHER
from aloecrypt.session.builder import PartyCHALLENGE as PartyCHALLENGE
from aloecrypt.session.builder import PartyCIPHER as PartyCIPHER
from aloecrypt.session.builder import PartyChallenge as PartyChallenge
from aloecrypt.session.builder import PartyINTRO as PartyINTRO
from aloecrypt.session.builder import PartyRESPONSE as PartyRESPONSE
from aloecrypt.session.builder import PartySecret as PartySecret
from aloecrypt.session.builder import SessionBuilder as SessionBuilder
from aloecrypt.session.message import MsgACK as MsgACK
from aloecrypt.session.message import MsgHELLO as MsgHELLO
from aloecrypt.session.message import MsgSYN as MsgSYN
from aloecrypt.session.message import MsgSYNACK as MsgSYNACK
from aloecrypt.session.message import MsgWELCOME as MsgWELCOME
from aloecrypt.session import AloecryptSession as AloecryptSession
from aloecrypt.session import CounterParty as CounterParty
from aloecrypt.session import Party as Party

class FromSecretsInput:
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

def perform_handshake(
    session_a: SessionBuilder,
    session_b: SessionBuilder,
) -> tuple[AloecryptSession, AloecryptSession]:
    """Run a full handshake between two SessionBuilder instances.

        Convenience function that drives the complete HELLO → SYN → ACK →
        SYNACK → WELCOME sequence in a single call. Both builders are mutated
        in place and the two resulting sessions are returned.

        Intended for testing and local use where both parties share a process.
        In production, each message would be serialised and transmitted
        separately using the individual make_* and on_counterparty_* methods.

        Args:
            session_a: A SessionBuilder created by party A, targeting B's address.
            session_b: A SessionBuilder created by party B, targeting A's address.

        Returns:
            A tuple of (session_a, session_b), both ready for encrypt/decrypt.

        Raises:
            Exception: If the handshake fails at any step, for example due to
                a signature mismatch or failed challenge response.

        Example:
    ```python
            delegate_a = signer_a.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)
            delegate_b = signer_b.create_delegate(EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0)

            session_a = SessionBuilder.create(signer_b.address, delegate_a)
            session_b = SessionBuilder.create(signer_a.address, delegate_b)

            built_a, built_b = perform_handshake(session_a, session_b)

            ciphertext = built_a.encrypt(b"hello")
            assert built_b.decrypt(ciphertext) == b"hello"
    ```
    """
    ...

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
