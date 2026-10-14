"""
Air-Gapped QR Optical Communication Module
Askeri Seviye Hava Boşluklu (Air-Gapped) Optik İletişim:
- Ağ bağlantısı (İnternet, Wi-Fi, Bluetooth) olmayan izole ortamlarda güvenli veri aktarımı
- Veriyi AES-256-GCM ile zırhlayıp dinamik / yüksek yoğunluklu QR koda dönüştürür
- Görüntü işleme (OpenCV) ile QR kodları çözüp kriptografik doğrulamayı yapar
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
    Düz metni (koordinat, tohum, anahtar) isteğe bağlı AES-256-GCM ile şifreler
    ve yüksek yoğunluklu QR kod PIL görüntüsüne dönüştürür.
    
    Returns:
        (PIL.Image, token_str)
    """
    if not plaintext.strip():
        raise ValueError("Aktarılacak veri boş olamaz.")

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


def decode_airgap_image(image_path: str) -> str:
    """
    Yüklenen QR kod görselini OpenCV ile okur ve içeriğindeki metni/token'ı döner.
    """
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Görsel bulunamadı: {image_path}")

    cv_img = cv2.imread(image_path)
    if cv_img is None:
        raise ValueError("Görsel dosyası okunamadı veya bozuk format.")

    detector = cv2.QRCodeDetector()
    val, pts, _ = detector.detectAndDecode(cv_img)
    if not val:
        # Görseli griye çevirip tekrar dene (robust fallback)
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        val, pts, _ = detector.detectAndDecode(gray)

    if not val:
        raise ValueError("Görsel içerisinde geçerli bir QR kod tespit edilemedi.")

    return val.strip()


def decrypt_airgap_token(token: str, passkey: Optional[str] = None) -> str:
    """
    QR koddan okunan token şifreli ise (AEGIS-MSG-v1) verilen parola ile çözer.
    Şifresiz ise doğrudan metni döner.
    """
    token = token.strip()
    if token.startswith("AEGIS-MSG-v1:"):
        if not passkey or not passkey.strip():
            raise VaultSecurityError("Bu QR kod AES-256-GCM ile zırhlanmıştır! Çözmek için lütfen parolayı girin.")
        payload = crypto_chat.decrypt_message(token, passkey.strip())
        return payload.get("text", "")
    return token
