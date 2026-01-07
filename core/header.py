"""
Stego file header utilities.

Design:
 - Header encapsulates metadata needed by the extractor:
   * magic (identifies our stego format)
   * version
   * salt (for KDF)
   * argon2 params (time, memory, parallelism)
   * wrapped_key (optional RSA-wrapped symmetric key)
   * nonce (for AES-GCM)
   * tag-length is implicit in AES-GCM output
   * payload_length (int)
 - The header itself is encrypted with a key derived from password,
   or with an RSA-wrapped symmetric key. This keeps metadata confidential.

Header is small and appended/prepended in a canonical binary format.
"""

import struct
import json
from typing import Optional

MAGIC = b'NEST'  # 4 bytes
VERSION = 1

def build_header(salt: bytes, argon2_params: dict, nonce: bytes, wrapped_key: Optional[bytes], payload_len: int) -> bytes:
    """
    Build a JSON-like header, then encode: MAGIC|version|len(header)|header-json-bytes
    Header json contains base64-ish encoded fields (we'll use hex to avoid dependencies).
    """
    header_obj = {
        "argon2": argon2_params,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "wrapped_key": wrapped_key.hex() if wrapped_key else None,
        "payload_len": payload_len
    }
    header_json = json.dumps(header_obj, separators=(',', ':'), sort_keys=True).encode('utf-8')
    header_len = len(header_json)
    return MAGIC + struct.pack(">B", VERSION) + struct.pack(">I", header_len) + header_json


def parse_header(data: bytes):
    """
    Parse header from the beginning of data.
    Returns (header_obj_dict, header_total_length).
    Raises ValueError on invalid/missing header.
    """
    if len(data) < 9:
        raise ValueError("Data too short for header")
    if data[:4] != MAGIC:
        raise ValueError("Invalid magic")
    version = data[4]
    header_len = struct.unpack(">I", data[5:9])[0]
    if len(data) < 9 + header_len:
        raise ValueError("Incomplete header")
    header_json = data[9:9+header_len]
    import json
    obj = json.loads(header_json.decode('utf-8'))
    # Normalize
    obj['salt'] = bytes.fromhex(obj['salt'])
    obj['nonce'] = bytes.fromhex(obj['nonce'])
    obj['wrapped_key'] = bytes.fromhex(obj['wrapped_key']) if obj.get('wrapped_key') else None
    return obj, 9 + header_len
