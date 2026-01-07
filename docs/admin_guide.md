"""
# Admin & Forensic Guide

Admin responsibilities:
- Manage admin password/key for log decryption and forensic mode.
- Rotate Argon2 parameters periodically and re-encrypt archives if necessary.
- Limit access to machines where NE is installed.

Forensic Mode:
- Forensic mode should be invoked on a secure, offline host.
- Use admin password to decrypt logs and to run metadata-only extraction (no content preview).
- Verify cryptographic hashes of original and stego files before operations.

Incident Response:
- If tampering is detected, the tool can be configured to zero out keys and optionally overwrite payload areas.
- Preserve original evidence copies for chain-of-custody.

Audit:
- Logs are encrypted and timestamped. Ensure admin password is backed up in an offline vault with authorized custodians.
"""
