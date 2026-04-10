# ./aloecrypt/_plugin.py
# License: Apache-2.0 (disclaimer at bottom of file)
from pydantic import BaseModel, field_validator
import importlib.resources
import extism
import msgpack

# ── Helpers ───────────────────────────────────────────────────────────────────


def _normalize(obj):
    """Recursively convert bytes -> list and decode bytes-keys in dicts so the
    structure round-trips cleanly through both Pydantic and msgpack."""
    if isinstance(obj, bytes):
        return list(obj)
    if isinstance(obj, dict):
        return {
            (k.decode() if isinstance(k, bytes) else k): _normalize(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    return obj


def _dump(val):
    """Serialize a value for msgpack. Pydantic models are dumped to plain
    dicts; everything else passes through."""
    if hasattr(val, "model_dump"):
        return val.model_dump()
    return val


def _pack(*args):
    """Pack one or more arguments for the plugin."""
    if len(args) == 1:
        return msgpack.packb(_dump(args[0]))
    # Each argument is independently msgpack-serialized into a bytes blob.
    # The outer array is then [bin, bin, bin, ...] which Rust deserializes
    # as Vec<Vec<u8>>, then each blob is deserialized individually.
    blobs = []
    for a in args:
        blob = msgpack.packb(_dump(a))
        blobs.append(blob)  # msgpack.packb always returns bytes
    return msgpack.packb(blobs, use_bin_type=True)


def _unpack(result):
    """Unpack plugin result and normalise bytes->list, bytes-keys->str."""
    return _normalize(msgpack.unpackb(result))


class _VarBytes:
    """Wrapper to mark bytes as variable-length (needs length prefix)."""
    def __init__(self, data: bytes):
        self.data = data

class _VarStr:
    """Wrapper to mark str as variable-length (needs length prefix)."""
    def __init__(self, data: str):
        self.data = data

def _wire_pack(*args):
    """Pack arguments as concatenated wire bytes for the plugin."""
    buf = bytearray()
    for a in args:
        if hasattr(a, 'to_wire_bytes'):
            buf.extend(a.to_wire_bytes())
        elif isinstance(a, _VarBytes):
            buf.extend(len(a.data).to_bytes(4, 'little'))
            buf.extend(a.data)
        elif isinstance(a, _VarStr):
            encoded = a.data.encode('utf-8')
            buf.extend(len(encoded).to_bytes(4, 'little'))
            buf.extend(encoded)
        elif isinstance(a, bool):
            buf.append(int(a))
        elif isinstance(a, int):
            buf.extend(a.to_bytes(8, 'little', signed=True))
        elif isinstance(a, bytes):
            # Fixed-size bytes (byte aliases, timestamps, etc.) — no length prefix
            buf.extend(a)
        elif isinstance(a, str):
            encoded = a.encode('utf-8')
            buf.extend(len(encoded).to_bytes(4, 'little'))
            buf.extend(encoded)
        else:
            raise TypeError(f"Cannot wire-pack type: {type(a)}")
    return bytes(buf)

class _PluginModel(BaseModel):
    model_config = {"frozen": True}

    @field_validator("*", mode="before")
    @classmethod
    def coerce_list_to_bytes(cls, v):
        if isinstance(v, list):
            return bytes(v)
        return v


class _Plugin:
    _instance = None

    def __new__(cls):
        # Singleton so we only load aloecrypt_plugin.wasm once
        if cls._instance is None:
            cls._instance = super(_Plugin, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_plugin'):
            return
        ref = importlib.resources.files("aloecrypt") / ".bin/aloecrypt_plugin.wasm"
        with importlib.resources.as_file(ref) as wasm_path:
            with open(wasm_path, "rb") as f:
                wasm_bytes = f.read()
        self._plugin = extism.Plugin(wasm_bytes, wasi=True)

    def pack(self, *args) -> bytes:
        if len(args) == 1:
            val = args[0]
            return msgpack.packb(
                val.model_dump() if hasattr(val, "model_dump") else val
            )
        return msgpack.packb(
            tuple(a.model_dump() if hasattr(a, "model_dump") else a for a in args)
        )

    def unpack(self, data: bytes) -> dict:
        return _normalize(msgpack.unpackb(data))

    def call(self, fn: str, payload: bytes) -> bytes:
        return self._plugin.call(fn, payload)

    def call_unpacked(self, fn: str, payload: bytes) -> dict:
        return self.unpack(self.call(fn, payload))


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
