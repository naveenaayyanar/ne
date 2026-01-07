"""
# Build Instructions (Windows & Optional Linux)

Prerequisites:
- Python 3.10+ (64-bit recommended)
- pip
- Recommended packages: cryptography, argon2-cffi, pillow, numpy, opencv-python, pyqt5, pyinstaller

Install dependencies:
```bash
pip install -r requirements.txt
```

Create an executable (Windows):
1. Install PyInstaller.
2. From repo root:
```bash
pyinstaller --onefile --name NE_Stego --add-data "resources;resources" gui/main.py
```
3. Test the generated `dist/NE_Stego.exe` thoroughly on target machines.

Notes:
- Code obfuscation: consider using PyArmor or commercial solutions after legal review.
- For high assurance, build in an isolated, air-gapped environment with reproducible build steps.

Windows specifics:
- Consider using Windows DPAPI or Credential Manager to store admin keys securely.
- Use code signing (EV certificate) for produced EXE in production deployments.
"""
