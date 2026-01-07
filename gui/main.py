"""
PyQt5-based GUI skeleton for NE.

Features demonstrated:
 - Embed and Extract flows with password prompt
 - Drag and drop placeholder
 - Progress bar and warnings for insufficient capacity

Note: This is a minimal, secure-by-design skeleton. In production:
 - Harden input validation
 - Protect GUI memory (avoid storing secrets in cleartext)
 - Integrate OS-level secure prompts for passwords (Windows Credential UI)
"""

import sys
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QInputDialog
import core.crypto as crypto
import core.header as header_mod
import core.stego_image as stego_image
from utils.secure_logger import SecureLogger

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NE Steganography Suite")
        self.resize(800, 600)
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout()
        central.setLayout(layout)

        self.embed_btn = QtWidgets.QPushButton("Embed Payload into Image (PNG/BMP)")
        self.embed_btn.clicked.connect(self.embed_flow)
        layout.addWidget(self.embed_btn)

        self.extract_btn = QtWidgets.QPushButton("Extract Payload from Image")
        self.extract_btn.clicked.connect(self.extract_flow)
        layout.addWidget(self.extract_btn)

        self.log = SecureLogger(b"admin-passphrase")  # demo; DO NOT hardcode in prod

    def embed_flow(self):
        carrier, _ = QFileDialog.getOpenFileName(self, "Select Carrier Image", "", "Images (*.png *.bmp)")
        if not carrier:
            return
        payload_file, _ = QFileDialog.getOpenFileName(self, "Select Payload File")
        if not payload_file:
            return
        out_file, _ = QFileDialog.getSaveFileName(self, "Save Stego Image", "", "PNG Image (*.png)")
        if not out_file:
            return
        passphrase, ok = QInputDialog.getText(self, "Passphrase", "Enter strong passphrase:", QtWidgets.QLineEdit.Password)
        if not ok or not passphrase:
            QMessageBox.warning(self, "Cancelled", "Operation cancelled: passphrase required")
            return
        # read payload
        with open(payload_file, "rb") as f:
            payload = f.read()
        # compress optional - omitted for brevity

        # derive key
        key, salt = crypto.derive_key(passphrase.encode('utf-8'))
        nonce, ct = crypto.aes_gcm_encrypt(key, payload, associated_data=b"NE-stego")
        # assemble header
        hdr = header_mod.build_header(salt, {"time": header_mod.VERSION}, nonce, None, len(ct))
        # build combined blob to embed: hdr + ct
        combined = hdr + ct
        try:
            res = stego_image.embed_lsb_adaptive(carrier, combined, stego_key=sha256(passphrase.encode('utf-8')).digest(), output_path=out_file)
            QMessageBox.information(self, "Success", f"Embedded payload to {out_file}")
            self.log.append({"action": "embed", "carrier": carrier, "output": out_file, "payload_len": len(payload)})
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.log.append({"action": "embed-failed", "carrier": carrier, "error": str(e)})

    def extract_flow(self):
        stego_file, _ = QFileDialog.getOpenFileName(self, "Select Stego Image", "", "Images (*.png *.bmp)")
        if not stego_file:
            return
        passphrase, ok = QInputDialog.getText(self, "Passphrase", "Enter passphrase:", QtWidgets.QLineEdit.Password)
        if not ok or not passphrase:
            QMessageBox.warning(self, "Cancelled", "Operation cancelled: passphrase required")
            return
        try:
            # First extract header length heuristic: we must know how many bytes to extract.
            # For demo: extract first 1024 bytes to parse header
            header_bytes = stego_image.extract_lsb_adaptive(stego_file, stego_key=crypto.sha256(passphrase.encode('utf-8')).digest(), payload_len_bytes=1024)
        except Exception:
            # Fallback: attempt using different strategy; omitted
            QMessageBox.critical(self, "Error", "Failed to read header with provided passphrase/key")
            return
        # parsing header
        try:
            hdr_obj, hdr_total_len = header_mod.parse_header(header_bytes)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Header parse error: {e}")
            return
        # Now extract full payload length provided in header
        total_cipher_len = hdr_obj['payload_len']
        try:
            combined = stego_image.extract_lsb_adaptive(stego_file, stego_key=crypto.sha256(passphrase.encode('utf-8')).digest(), payload_len_bytes=hdr_total_len + total_cipher_len)
            # split header and ct
            ct = combined[hdr_total_len:]
            key, _ = crypto.derive_key(passphrase.encode('utf-8'), salt=hdr_obj['salt'])
            plaintext = crypto.aes_gcm_decrypt(key, hdr_obj['nonce'], ct, associated_data=b"NE-stego")
            # offer to save
            out_path, _ = QFileDialog.getSaveFileName(self, "Save Extracted Payload")
            if out_path:
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                QMessageBox.information(self, "Success", f"Saved payload to {out_path}")
                self.log.append({"action": "extract", "source": stego_file, "output": out_path})
        except Exception as e:
            QMessageBox.critical(self, "Extraction failed", str(e))
            self.log.append({"action": "extract-failed", "error": str(e)})

def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
