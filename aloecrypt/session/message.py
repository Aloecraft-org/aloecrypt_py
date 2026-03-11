# ./aloecrypt/session/message.py
# License: Apache-2.0 (disclaimer at bottom of file)
# Generated - Do Not Modify
# file: aloecrypt/session/builder.py
from aloecrypt._plugin import _PluginModel
from aloecrypt.signatory import *
from aloecrypt.kem import *
from aloecrypt.session.builder import *


class MsgACK(_PluginModel):
    cipher: PartyCIPHER
    challenge: PartyCHALLENGE


class MsgHELLO(_PluginModel):
    address: bytes
    intro: PartyINTRO


class MsgSYN(_PluginModel):
    intro: PartyINTRO
    cipher: PartyCIPHER


class MsgSYNACK(_PluginModel):
    challenge: PartyCHALLENGE
    challenge_response: PartyRESPONSE


class MsgWELCOME(_PluginModel):
    challenge_response: PartyRESPONSE


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
