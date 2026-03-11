# ./aloecrypt/consts.py
# License: Apache-2.0 (disclaimer at bottom of file)

KEY_ITERS: int = 4096
COM_STRUCT_ID: str = "AloeBuffer.0"
KYBER_CANONICAL_SEED: str = "AloecryptKyber.0"
KYBER_CANONICAL_SALT: str = "AloecryptKyber.1"
MAGIC_BYTES: bytes = bytes(
    [
        0x41,
        0x4C,
        0x4F,
        0x45,
        0x43,
        0x52,
        0x59,
        0x50,
        0x54,
        0x69,
        0x61,
        0x6D,
        0x6D,
        0x69,
        0x6B,
        0x65,
    ]
)

PUBLIC_ADDR_PEM_TAG: str = "ALOECRYPT PUBLIC ADDR"
ROOT_ADDR_PEM_TAG: str = "ALOECRYPT ROOT ADDR"
ROOT_KEY_PEM_TAG: str = "ALOECRYPT ROOT KEY"
PEER_KYBER_PEM_TAG: str = "ALOECRYPT PEER KYBER"
KYBER_KEY_PEM_TAG: str = "ALOECRYPT KYBER KEY"
PEM_CHUNK_SZ: int = 32
ADDRESS_SZ: int = 32  # HMAC
VERIFY_KEY_SZ: int = 1952  # DILITHIUM pubkey
SIGN_KEY_SZ: int = 4032  # DILITHIUM privkey
SIGNATURE_SZ: int = 3309  # DILITHIUM signature
ENCAPSULATE_KEY_SZ: int = 1184  # KYBER pubkey
DECAPSULATE_KEY_SZ: int = 2400  # KYBER privkey
CIPHER_SZ: int = 1088
SECRET_SZ: int = 32
TIMESTAMP_SZ: int = 8
CHACHA_NONCE_SZ: int = 12
SESSION_NONCE_SZ: int = 32
SESSION_SALT_SZ: int = 32
SESSION_SALT_HASH_ITERS: int = 512
ENCRYPTED_TAG_SZ: int = 16  # CHACHA20POLY1305
ENCRYPTED_NONCE_SZ: int = SESSION_NONCE_SZ + 2 * ENCRYPTED_TAG_SZ

EMPTY_SIGNATURE: bytes = bytes(SIGNATURE_SZ)
EMPTY_ADDRESS: bytes = bytes(ADDRESS_SZ)
EMPTY_TIMESTAMP: bytes = bytes(TIMESTAMP_SZ)

SESSION_SALT_INFO: bytes = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
SESSION_CHACHA_KEY_INFO: bytes = bytes.fromhex("e0f1f2f3f4f5f6f7f8f9")
SESSION_CHACHA_NONCE_INFO: bytes = bytes.fromhex("d0f1f2f3f4f5f6f7f8f9")
SESSION_MSG_NONCE_INFO: bytes = bytes.fromhex("c0f1f2f3f4f5f6f7f8f9")

STABLE_SALT_INFO: bytes = bytes.fromhex("f1f1f2f3f4f5f6f7f8f9")
STABLE_CHACHA_KEY_INFO: bytes = bytes.fromhex("e1f1f2f3f4f5f6f7f8f9")
STABLE_CHACHA_NONCE_INFO: bytes = bytes.fromhex("d1f1f2f3f4f5f6f7f8f9")
STABLE_MSG_NONCE_INFO: bytes = bytes.fromhex("c1f1f2f3f4f5f6f7f8f9")

NONCE_SYN_STABLE_SEED: str = "AloecryptSYN.0"
NONCE_SYN_SESSION_SEED: str = "AloecryptSYN.1"
NONCE_ACK_STABLE_SEED: str = "AloecryptACK.0"
NONCE_ACK_SESSION_SEED: str = "AloecryptACK.1"
NONCE_SYNACK_STABLE_SEED: str = "AloecryptSYNACK.0"
NONCE_SYNACK_SESSION_SEED: str = "AloecryptSYNACK.1"

NONCE_MSG_STABLE_SEED: str = "AloecryptMSG.0"
NONCE_MSG_SESSION_SEED: str = "AloecryptMSG.1"

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
