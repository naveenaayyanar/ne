"""
# NE User Guide

This guide explains how to embed and extract payloads using NE.

High-level flow:
1. Prepare payload (file) to embed.
2. Choose carrier (image/audio/video/text).
3. Choose a strong passphrase. For best security use a high-entropy passphrase or an appropriate key file.
4. NE will:
   - Compress payload (optional)
   - Encrypt payload (AES-GCM with key derived via Argon2id)
   - Build an encrypted header with necessary metadata
   - Embed ciphertext across the chosen carrier using an algorithm appropriate to the format
   - Generate tamper-evident HMAC/AEAD for the stego file

Extraction:
- Provide the stego file, correct passphrase (or RSA private key if wrapped), and NE will verify integrity and decrypt the payload.

Important recommendations:
- Use lossless image formats (PNG/BMP) for LSB methods; for JPEG use DCT-based embedding.
- Keep Argon2 memory/time parameters high on modern hardware for anti-bruteforce.
- Use admin-only forensic mode for sensitive operations.

See the CLI and GUI for step-by-step operations.
"""
