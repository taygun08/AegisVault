"""
Cryptographic Chat & Secure Armored Messenger
Capabilities:
- End-to-End Encrypted Messaging (E2EE)
- AES-256-GCM + scrypt Armored Envelope Format (AEGIS-MSG-v1)
- Authenticated Data Integrity (Tamper-Proof GHASH Tag)
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
    Encrypts a plaintext message using AES-256-GCM and a shared passkey.
    The resulting armored string can be copied via any insecure transport channel.
    """
    if not plaintext.strip():
        raise ValueError("Message body cannot be empty.")
    if not shared_passkey.strip():
        raise ValueError("Shared passkey cannot be empty.")

    # Envelope structure containing message content and ISO timestamp
    envelope = {
        "text": plaintext.strip(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    raw_payload = json.dumps(envelope, ensure_ascii=False)
    encrypted_armored = MilitaryVault.encrypt(raw_payload, shared_passkey)

    return f"{MSG_PREFIX}:{encrypted_armored}"


def decrypt_message(token: str, shared_passkey: str) -> Dict[str, Any]:
    """
    Decrypts an armored message token and validates cryptographic integrity.
    """
    token = token.strip()
    if not token.startswith(MSG_PREFIX + ":"):
        raise ValueError("Invalid message format! Must start with 'AEGIS-MSG-v1:'.")

    armored_content = token[len(MSG_PREFIX) + 1:]
    decrypted_bytes = MilitaryVault.decrypt(armored_content, shared_passkey)
    raw_payload = decrypted_bytes.decode("utf-8")
    return json.loads(raw_payload)
