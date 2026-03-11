# ./aloecrypt/signatory.py
# License: Apache-2.0 (disclaimer at bottom of file)
# Generated - Do Not Modify
# file: aloecrypt/signatory.py
from aloecrypt._plugin import _PluginModel


class DilithiumSigner(_PluginModel):
    dlt_pubkey: bytes
    dlt_privkey: bytes
    dlt_sig_bytes: bytes
    dlt_address: bytes
    dlt_auth_id: bytes
    dlt_created_at: bytes
    dlt_active_from: bytes
    dlt_expires_at: bytes
    dlt_refresh_count: int
    dlt_max_refresh: int


class DilithiumVerifier(_PluginModel):
    dlt_pubkey: bytes
    dlt_sig_bytes: bytes
    dlt_address: bytes
    dlt_auth_id: bytes
    dlt_created_at: bytes
    dlt_active_from: bytes
    dlt_expires_at: bytes
    dlt_refresh_count: int
    dlt_max_refresh: int


class XDilithiumSigner(_PluginModel):
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
