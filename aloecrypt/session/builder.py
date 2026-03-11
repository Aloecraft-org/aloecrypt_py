# ./aloecrypt/session/builder.py
# License: Apache-2.0 (disclaimer at bottom of file)
# Generated - Do Not Modify
# file: aloecrypt/session/builder.py
from typing import Optional

from aloecrypt._plugin import _PluginModel
from aloecrypt.signatory import *
from aloecrypt.kem import *


class FullCIPHER(_PluginModel):
    stable_cipher: bytes
    session_cipher: bytes
    stable_secret: bytes
    session_secret: bytes
    signature: bytes


class PartyCHALLENGE(_PluginModel):
    encrypted_challenge: bytes
    encrypted_check: bytes


class PartyCIPHER(_PluginModel):
    stable_cipher: bytes
    session_cipher: bytes
    signature: bytes


class PartyChallenge(_PluginModel):
    encrypted_challenge: bytes
    encrypted_check: bytes
    decrypted_challenge: bytes
    decrypted_check: bytes


class PartyINTRO(_PluginModel):
    address: bytes
    nonce: bytes
    stable_kem: KyberPublicKEM
    session_kem: KyberPublicKEM
    verifier: DilithiumVerifier


class PartyRESPONSE(_PluginModel):
    decrypted_challenge: bytes


class PartySecret(_PluginModel):
    stable_secret: bytes
    session_secret: bytes
    signature: bytes


class SessionBuilder(_PluginModel):
    delegate_signer: DilithiumSigner
    stable_kem: KyberFullKEM
    session_kem: KyberFullKEM
    nonce: bytes
    challenge_nonce: bytes
    session_salt: Optional[bytes]
    signature: Optional[bytes]
    cipher: Optional[FullCIPHER]
    counterparty_intro: Optional[PartyINTRO]
    counterparty_cipher: Optional[PartySecret]
    counterparty_challenge: Optional[PartyChallenge]
    build_ready: bool


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
