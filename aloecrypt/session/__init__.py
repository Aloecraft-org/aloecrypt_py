# ./aloecrypt/session/__init__.py
# License: Apache-2.0 (disclaimer at bottom of file)
# Generated - Do Not Modify
# file: aloecrypt/session/__init__.py
from aloecrypt._plugin import _PluginModel
from aloecrypt.signatory import *
from aloecrypt.kem import *


class CounterParty(_PluginModel):
    address: bytes
    nonce: bytes
    signature: bytes
    stable_kem: KyberPublicKEM
    session_kem: KyberPublicKEM
    verifier: DilithiumVerifier
    stable_secret: bytes
    session_secret: bytes


class Party(_PluginModel):
    nonce: bytes
    session_signature: bytes
    delegate_signer: DilithiumSigner
    stable_kem: KyberFullKEM
    session_kem: KyberFullKEM
    stable_secret: bytes
    session_secret: bytes


class AloecryptSession(_PluginModel):
    party: Party
    counter_party: CounterParty
    session_salt: (
        bytes  # Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
    )


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
