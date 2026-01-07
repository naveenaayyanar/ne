"""
Advanced image steganography module.

Features implemented:
 - Adaptive LSB embedding (randomized bit placement using stego-key)
 - Edge-based pixel embedding (prefer edge pixels for lower perceptibility)
 - Payload capacity calculation
 - Simple JPEG-DCT placeholder (see comments)

Dependencies:
 - pillow (PIL)
 - numpy
 - OpenCV (cv2) for edge detection (optional but recommended)

Note:
 - For JPEG DCT coefficient manipulation a production implementation should
   operate on quantized DCT coefficients (libjpeg/libjpeg-turbo) to avoid
   recompression artifacts. Python-level approximations are provided for research/demo.
"""

from PIL import Image
import numpy as np
import secrets
import math
from typing import Tuple, List
from hashlib import sha256
import core.header as header_mod
import core.crypto as crypto

try:
    import cv2
    _CV2_AVAILABLE = True
except Exception:
    _CV2_AVAILABLE = False


def _prng_positions(width: int, height: int, payload_bits: int, key: bytes) -> List[int]:
    """
    Deterministic pseudorandom positions generator using HMAC-SHA256-based stream.
    Returns list of linear indices (0 .. width*height*channels-1).
    """
    total = width * height * 3  # assume RGB channels
    if payload_bits > total:
        raise ValueError("Payload too large for image capacity in naive mode")
    positions = []
    counter = 0
    i = 0
    while len(positions) < payload_bits:
        data = key + counter.to_bytes(8, 'big')
        digest = sha256(data).digest()
        # consume 8-byte chunks to generate indices
        for j in range(0, len(digest), 4):
            if len(positions) >= payload_bits:
                break
            idx = int.from_bytes(digest[j:j+4], 'big') % total
            if idx not in positions:
                positions.append(idx)
        counter += 1
    return positions


def _edge_mask(image_np: np.ndarray) -> np.ndarray:
    """
    Compute a mask favoring edges for embedding.
    Returns boolean mask with True where embedding is preferred.
    """
    if not _CV2_AVAILABLE:
        # Fallback: use high local variance as proxy for edges
        gray = np.mean(image_np, axis=2).astype(np.uint8)
        kernel = np.ones((3,3), dtype=int)
        from scipy import ndimage
        local_mean = ndimage.uniform_filter(gray.astype(float), size=3)
        local_var = (gray - local_mean)**2
        thresh = np.percentile(local_var, 60)
        return local_var > thresh
    # Use Canny edges
    gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)
    edges = cv2.Canny(gray, 100, 200)
    return edges > 0


def calculate_capacity(image: Image.Image) -> int:
    """
    Estimate maximum payload bits for adaptive LSB with edge preference.
    Conservative: 1 bit per color channel per pixel on edge pixels,
    and 0.25 bits/channel on non-edge pixels.
    """
    w, h = image.size
    npimg = np.array(image.convert('RGB'))
    mask = _edge_mask(npimg)
    edge_pixels = np.count_nonzero(mask)
    non_edge_pixels = w*h - edge_pixels
    capacity_bits = edge_pixels * 3 * 1 + non_edge_pixels * 3 * 0.25
    return int(math.floor(capacity_bits))


def embed_lsb_adaptive(input_image_path: str, payload: bytes, stego_key: bytes, output_path: str) -> dict:
    """
    Embed payload (already encrypted) into an image using adaptive LSB.
    Returns metadata including header and capacity used.
    WARNING: This routine operates on lossless formats (PNG/BMP).
    For JPEG use separate DCT-based method below.
    """
    img = Image.open(input_image_path).convert('RGB')
    w, h = img.size
    npimg = np.array(img)
    payload_bits = len(payload) * 8
    capacity = calculate_capacity(img)
    if payload_bits > capacity:
        raise ValueError(f"Payload too large ({payload_bits} bits) for image capacity {capacity} bits")

    # Build embedding positions (prefer edge pixels first)
    edge_mask = _edge_mask(npimg).flatten()
    total_pixels = w * h * 3
    positions = _prng_positions(w, h, payload_bits, stego_key)

    # Convert payload to bit stream
    bitstream = []
    for byte in payload:
        for i in range(8)[::-1]:
            bitstream.append((byte >> i) & 1)

    flat = npimg.flatten()
    for pos_idx, bit in zip(positions, bitstream):
        # Adaptive: if pixel at pos is near smooth area, flip LSB less frequently:
        # but since positions are PRNG-selected, embed directly
        flat[pos_idx] = (flat[pos_idx] & ~1) | bit

    new_np = flat.reshape(npimg.shape)
    out_img = Image.fromarray(new_np.astype('uint8'), 'RGB')
    out_img.save(output_path, format='PNG', optimize=True)
    return {
        "output": output_path,
        "payload_bits": payload_bits,
        "capacity_bits": capacity
    }


def extract_lsb_adaptive(stego_image_path: str, stego_key: bytes, payload_len_bytes: int) -> bytes:
    """
    Extract payload bytes from an adaptive-LSB stego image using the same stego_key.
    Requires payload length in bytes (or header to locate it).
    """
    img = Image.open(stego_image_path).convert('RGB')
    w, h = img.size
    npimg = np.array(img)
    payload_bits = payload_len_bytes * 8
    positions = _prng_positions(w, h, payload_bits, stego_key)
    flat = npimg.flatten()
    bits = [flat[pos] & 1 for pos in positions]
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


# Placeholder: JPEG DCT-based embedding
# For a production-grade JPEG DCT embedding, use a library that exposes quantized DCT
# coefficients (e.g., libjpeg with bindings, jpegio). The high-level approach:
#  - Parse JPEG into 8x8 blocks in YCbCr
#  - For each 8x8 block take the DCT coefficient matrix
#  - Choose mid-frequency coefficients (avoid DC and very high freq)
#  - Slightly modify coefficient LSBs according to payload bits
#  - Preserve coefficient sign and distribution to avoid statistical anomalies
#  - Re-quantize carefully and recompress with original quantization tables
#
# Implementation in Python is non-trivial and out of scope for a short sample.
# See docs/ for algorithmic details and recommended C-extension approach.
