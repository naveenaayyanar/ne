"""
# Simple script to package core stego modules into a zip for distribution.

import zipfile
import os

ROOT = os.path.dirname(os.path.dirname(__file__))
OUT = os.path.join(ROOT, 'ne_stego_core.zip')
FILES = [
    'core/crypto.py', 'core/header.py', 'core/stego_image.py', 'core/stego_audio.py',
    'core/stego_video.py', 'core/stego_text.py', 'utils/secure_logger.py'
]

with zipfile.ZipFile(OUT, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    for f in FILES:
        z.write(os.path.join(ROOT, f), arcname=f)

print('Created', OUT)
"""