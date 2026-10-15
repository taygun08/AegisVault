"""
Air-Gapped QR Optical Communication Module
Military-Grade Air-Gapped Optical Communication:
- Secure data exchange across physically isolated systems without Wi-Fi, Ethernet, or Bluetooth.
- Armors payload using AES-256-GCM before rendering into high-density optical QR codes.
- Decodes QR frames via OpenCV computer vision and verifies cryptographic integrity.
"""

import os
from typing import Tuple, Optional, Dict, Any
from PIL import Image
import qrcode
import cv2
import crypto_chat
from military_vault import VaultSecurityError


def generate_airgap_qr(plaintext: str, passkey: Optional[str] = None) -> Tuple[Image.Image, str]:
    """
    Encrypts plaintext (coordinates, seed phrases, private keys) with optional AES-256-GCM
    and transforms the ciphertext into a high-density QR code PIL image.
    
    Returns:
        (PIL.Image, token_str)
    """
    if not plaintext.strip():
        raise ValueError("Data payload cannot be empty.")

    if passkey and passkey.strip():
        token = crypto_chat.encrypt_message(plaintext.strip(), passkey.strip())
    else:
        token = plaintext.strip()

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2
    )
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img, token


import numpy as np


def decode_airgap_image(image_path: str) -> str:
    """
    Decodes an image containing a QR code using OpenCV and returns the raw decoded token.
    Supports non-ASCII and Unicode file paths on Windows.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")

    # Use numpy.fromfile + cv2.imdecode for Windows Unicode file path resilience
    try:
        file_bytes = np.fromfile(image_path, dtype=np.uint8)
        cv_img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    except Exception:
        cv_img = cv2.imread(image_path)

    if cv_img is None:
        raise ValueError("Could not read image file or unsupported format.")

    detector = cv2.QRCodeDetector()
    val, pts, _ = detector.detectAndDecode(cv_img)
    if not val:
        # Fallback to grayscale for higher contrast detection
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        val, pts, _ = detector.detectAndDecode(gray)

    if not val:
        raise ValueError("No valid optical QR code detected in the image.")

    return val.strip()


def decrypt_airgap_token(token: str, passkey: Optional[str] = None) -> str:
    """
    Decrypts an encrypted QR token (AEGIS-MSG-v1) using the shared passkey.
    Returns plain text directly if unencrypted.
    """
    token = token.strip()
    if token.startswith("AEGIS-MSG-v1:"):
        if not passkey or not passkey.strip():
            raise VaultSecurityError("This QR code is AES-256-GCM armored! Please enter the decryption passkey.")
        payload = crypto_chat.decrypt_message(token, passkey.strip())
        return payload.get("text", "")
    return token
