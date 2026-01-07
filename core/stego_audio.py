"""
Audio steganography module (WAV).

Features:
 - LSB embedding for WAV (PCM) with randomized positions
 - Phase coding placeholder (advanced psychoacoustic-aware embedding)
 - Capacity estimation
"""

import wave
import numpy as np
from hashlib import sha256
import secrets
import core.crypto as crypto

def calculate_wav_capacity(wav_path: str, lsb_count: int = 1) -> int:
    with wave.open(wav_path, 'rb') as wf:
        nframes = wf.getnframes()
        nchannels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        # capacity in bits
        return nframes * nchannels * lsb_count

def _prng_positions_audio(n_samples: int, payload_bits: int, key: bytes):
    positions = []
    counter = 0
    while len(positions) < payload_bits:
        data = key + counter.to_bytes(8, 'big')
        digest = sha256(data).digest()
        for j in range(0, len(digest), 4):
            if len(positions) >= payload_bits:
                break
            idx = int.from_bytes(digest[j:j+4], 'big') % n_samples
            if idx not in positions:
                positions.append(idx)
        counter += 1
    return positions

def embed_wav_lsb(input_wav: str, payload: bytes, stego_key: bytes, output_wav: str, lsb_count: int = 1):
    with wave.open(input_wav, 'rb') as r:
        params = r.getparams()
        frames = r.readframes(params.nframes)
        samples = np.frombuffer(frames, dtype=np.int16)  # assumes 16-bit PCM; production must handle formats
    payload_bits = len(payload) * 8
    capacity = len(samples) * lsb_count
    if payload_bits > capacity:
        raise ValueError("Payload too large for WAV capacity")
    positions = _prng_positions_audio(len(samples), payload_bits, stego_key)
    bitstream = []
    for byte in payload:
        for i in range(8)[::-1]:
            bitstream.append((byte >> i) & 1)
    samples_mod = samples.copy()
    for pos, bit in zip(positions, bitstream):
        samples_mod[pos] = (samples_mod[pos] & ~1) | bit
    with wave.open(output_wav, 'wb') as w:
        w.setparams(params)
        w.writeframes(samples_mod.tobytes())
    return {"output": output_wav, "payload_bits": payload_bits, "capacity_bits": capacity}

def extract_wav_lsb(stego_wav: str, stego_key: bytes, payload_len_bytes: int) -> bytes:
    with wave.open(stego_wav, 'rb') as r:
        params = r.getparams()
        frames = r.readframes(params.nframes)
        samples = np.frombuffer(frames, dtype=np.int16)
    payload_bits = payload_len_bytes * 8
    positions = _prng_positions_audio(len(samples), payload_bits, stego_key)
    bits = [samples[pos] & 1 for pos in positions]
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)
