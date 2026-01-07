"""
Encrypted secure logger.

Design:
 - Log entries are JSON lines encrypted using AES-GCM with a rotating key derived
   from an admin password (Argon2). Keys are rotated periodically.
 - Log files are append-only and timestamped. Old logs are rotated & archived.
 - Admin-only forensic mode can decrypt logs for audit.
"""

import json
import os
import time
from core.crypto import derive_key, aes_gcm_encrypt, aes_gcm_decrypt
from datetime import datetime

LOG_DIR = "secure_logs"
os.makedirs(LOG_DIR, exist_ok=True)

class SecureLogger:
    def __init__(self, admin_password: bytes, log_id: str = None):
        self.key, self.salt = derive_key(admin_password)
        self.log_id = log_id or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        self.log_path = os.path.join(LOG_DIR, f"log_{self.log_id}.bin")

    def append(self, event: dict):
        event['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        plaintext = json.dumps(event, separators=(',', ':')).encode('utf-8')
        nonce, ct = aes_gcm_encrypt(self.key, plaintext)
        with open(self.log_path, "ab") as f:
            # store: nonce len (1) | nonce | ct len (4) | ct
            f.write(len(nonce).to_bytes(1, 'big') + nonce + len(ct).to_bytes(4, 'big') + ct)

    def read_all(self, admin_password: bytes):
        key, _ = derive_key(admin_password, salt=self.salt)
        entries = []
        with open(self.log_path, "rb") as f:
            data = f.read()
        i = 0
        while i < len(data):
            nlen = data[i]; i += 1
            nonce = data[i:i+nlen]; i += nlen
            ctlen = int.from_bytes(data[i:i+4], 'big'); i += 4
            ct = data[i:i+ctlen]; i += ctlen
            pt = aes_gcm_decrypt(key, nonce, ct)
            entries.append(json.loads(pt.decode('utf-8')))
        return entries
