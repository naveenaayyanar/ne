"""
# Threat Model & Security Considerations

Actors:
- Legitimate user (embed/extract)
- Adversary performing passive steganalysis (statistical detection)
- Active adversary that tampers with carrier media
- Offline brute-force attacker trying passwords or searching payloads
- Hostile insider with physical access to system

Assumptions:
- Adversary may have copies of original carrier or large corpora for statistical analysis.
- Adversary cannot break AES-256 or Argon2 with recommended parameters.

Mitigations:
- Encrypt payload with AES-256-GCM; Argon2id for password derivation.
- Randomized embedding and use of edge areas reduces statistical artifacts.
- Header encryption + AEAD prevents tag stripping without detection.
- Tamper detection causes payload self-destruct or denial of extraction.
- Secure logs encrypted and access-controlled.

Limitations:
- Text steganography is fragile to normalization.
- Lossy recompression (e.g., recompressing a PNG to JPEG) will likely destroy LSB payloads.
- Sophisticated steganalysis can detect anomalies; continuous evaluation required for academic research.

Operational security:
- Keep keys off networked storage where possible.
- Use admin-only forensic mode for investigations.
- Rotate keys and audit logs.
"""
