"""
Cryptographic Chat & Secure Armored Messenger
Özellikler:
- Uçtan Uca Şifreli Mesajlaşma (E2EE)
- AES-256-GCM + scrypt Zırhlı Mesaj Formatı (AEGIS-MSG-v1)
- Tam Bütünlük Doğrulaması (Kurcalanamaz / Değiştirilemez)
"""

import os
import base64
import json
from datetime import datetime
from typing import Dict, Any, Tuple
from military_vault import MilitaryVault, VaultSecurityError

MSG_PREFIX = "AEGIS-MSG-v1"


def encrypt_message(plaintext: str, shared_passkey: str) -> str:
    """
    Metin mesajını ortak parola ile AES-256-GCM kullanarak zırhlar.
    Çıktı WhatsApp, Telegram veya e-posta ile kopyalanıp gönderilebilir.
    """
    if not plaintext.strip():
        raise ValueError("Mesaj metni boş olamaz.")
    if not shared_passkey.strip():
        raise ValueError("Ortak parola boş olamaz.")

    # Zarf verisi (Mesaj + Zaman Damgası)
    envelope = {
        "text": plaintext.strip(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    raw_payload = json.dumps(envelope, ensure_ascii=False)
    encrypted_armored = MilitaryVault.encrypt(raw_payload, shared_passkey)

    # İnsan tarafından tanınabilir zırhlı token
    return f"{MSG_PREFIX}:{encrypted_armored}"


def decrypt_message(token: str, shared_passkey: str) -> Dict[str, Any]:
    """
    Zırhlı mesaj token'ını çözer ve bütünlüğünü doğrular.
    """
    token = token.strip()
    if not token.startswith(MSG_PREFIX + ":"):
        raise ValueError("Geçersiz mesaj formatı! 'AEGIS-MSG-v1:' ile başlamalıdır.")

    armored_content = token[len(MSG_PREFIX) + 1:]
    decrypted_bytes = MilitaryVault.decrypt(armored_content, shared_passkey)
    raw_payload = decrypted_bytes.decode("utf-8")
    return json.loads(raw_payload)
