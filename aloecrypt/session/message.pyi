# ./aloecrypt/session/message.pyi
# License: Apache-2.0 (disclaimer at bottom of file)
# Generated - Do Not Modify
# file: aloecrypt/session/message.pyi

from aloecrypt.session.builder import (
    PartyCHALLENGE,
    PartyCIPHER,
    PartyINTRO,
    PartyRESPONSE,
)

class MsgACK:
    cipher: PartyCIPHER
    challenge: PartyCHALLENGE

class MsgHELLO:
    address: bytes
    intro: PartyINTRO

class MsgSYN:
    intro: PartyINTRO
    cipher: PartyCIPHER

class MsgSYNACK:
    challenge: PartyCHALLENGE
    challenge_response: PartyRESPONSE

class MsgWELCOME:
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
