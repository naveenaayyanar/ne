"""
Video steganography (MP4) module.

Strategy:
 - Use OpenCV (cv2) to read frames
 - Randomly select frames using stego-key (frame-randomization)
 - Embed payload across frames using image-module methods (adaptive LSB on frames)
 - Write output video preserving codec/container if possible (requires careful pipeline)
 - For research-grade robustness prefer lossless intermediate or H.264 with high quality and keeping quantization low.
"""

import cv2
import os
import math
from typing import List
import numpy as np
import core.stego_image as stego_image

def embed_in_video(input_mp4: str, payload: bytes, stego_key: bytes, output_mp4: str, frames_to_use_ratio: float = 0.5):
    cap = cv2.VideoCapture(input_mp4)
    if not cap.isOpened():
        raise IOError("Cannot open input video")
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)

    # Decide which frames to use
    import hashlib
    total_capacity = 0
    frames_idx = []
    # Build deterministic PRNG for frame indices
    counter = 0
    while len(frames_idx) < max(1, int(frame_count * frames_to_use_ratio)):
        digest = hashlib.sha256(stego_key + counter.to_bytes(8, 'big')).digest()
        for j in range(0, len(digest), 2):
            if len(frames_idx) >= int(frame_count * frames_to_use_ratio):
                break
            idx = int.from_bytes(digest[j:j+2], 'big') % frame_count
            if idx not in frames_idx:
                frames_idx.append(idx)
        counter += 1
    frames_idx.sort()

    # Read frames, embed progressively
    writer = cv2.VideoWriter(output_mp4, cv2.VideoWriter_fourcc(*'mp4v'), fps, (width, height))
    payload_ptr = 0
    payload_len = len(payload)
    for fidx in range(frame_count):
        ret, frame = cap.read()
        if not ret:
            break
        if fidx in frames_idx and payload_ptr < payload_len:
            # Determine how many bytes we can embed in this frame
            # Use stego_image.calculate_capacity to estimate bits
            pil_img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            cap_bits = stego_image.calculate_capacity(pil_img)
            cap_bytes = cap_bits // 8
            chunk = payload[payload_ptr:payload_ptr+cap_bytes]
            # Use a temp file approach: embed and reconvert
            tmp_in = f"frame_{fidx}_in.png"
            tmp_out = f"frame_{fidx}_out.png"
            pil_img.save(tmp_in, format='PNG')
            stego_image.embed_lsb_adaptive(tmp_in, chunk, stego_key, tmp_out)
            new_frame = cv2.cvtColor(np.array(Image.open(tmp_out).convert('RGB')), cv2.COLOR_RGB2BGR)
            # cleanup
            os.remove(tmp_in)
            os.remove(tmp_out)
            writer.write(new_frame)
            payload_ptr += len(chunk)
        else:
            writer.write(frame)
    cap.release()
    writer.release()
    if payload_ptr < payload_len:
        raise ValueError("Payload not fully embedded; insufficient capacity")
    return {"output": output_mp4, "payload_bytes_embedded": payload_ptr}
