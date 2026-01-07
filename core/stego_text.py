"""
Text steganography methods.

Techniques:
 - Unicode homoglyph substitution (careful with normalization)
 - Zero-width characters insertion (ZWSP, ZWNJ, etc.)
 - Whitespace steganography (spaces/tabs/newline patterns)
 - Semantic steganography suggested as an advanced module (requires NLP)

Security notes:
 - Text steganography is highly fragile to transformations (normalization, reflow).
 - Use in closed-channels or as part of multi-layer (e.g., encrypted + integrity-checked)
"""

ZW_CHARS = {
    'ZWSP': '\u200B',  # zero width space
    'ZWNJ': '\u200C',
    'ZWJ': '\u200D',
    'NBSP': '\u00A0'
}

def embed_zero_width(input_text: str, payload: bytes) -> str:
    """
    Encode payload as bits and insert zero-width chars between words.
    Very low visibility, but fragile to strip/normalization.
    """
    bits = ''.join(f"{b:08b}" for b in payload)
    words = input_text.split(' ')
    out_words = []
    bit_iter = iter(bits)
    for w in words:
        try:
            b = next(bit_iter)
            zw = ZW_CHARS['ZWSP'] if b == '1' else ''
            out_words.append(w + zw)
        except StopIteration:
            out_words.append(w)
    # append remaining bits as trailing zero-widths
    remaining = ''.join(bit_iter)
    out = ' '.join(out_words)
    if remaining:
        out += ''.join(ZW_CHARS['ZWSP'] if c == '1' else '' for c in remaining)
    return out

def extract_zero_width(stego_text: str, payload_len_bytes: int) -> bytes:
    bits = []
    count_bits = payload_len_bytes * 8
    for ch in stego_text:
        if ch == ZW_CHARS['ZWSP']:
            bits.append('1')
        # We treat absence as 0 only when we know positions; robust parsing requires separators
        if len(bits) >= count_bits:
            break
    # pad/truncate
    bits = bits[:count_bits] + ['0'] * max(0, count_bits - len(bits))
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = int(''.join(bits[i:i+8]), 2)
        out.append(byte)
    return bytes(out)
