"""
Vault Storage Manager (Multi-User Profiles & Hardware Binding)
Features:
- Multi-User Profile Management (Independent vault and credentials per user/machine)
- Hardware-Bound Profiles (Hardware fingerprint binding - vault cannot be opened on other PCs)
- Duress Password Support (Decoy vault with plausible deniability)
- Cold Storage Cryptocurrency Portfolio Storage
- Anti-Brute-Force Rate Limiting
"""

import os
import json
import secrets
import string
import uuid
import time
import platform
import hashlib
import base64
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
from military_vault import MilitaryVault, VaultSecurityError

PROFILES_DIR = "profiles"
DEFAULT_VAULT_FILE = "vault_data.mvat"
DEFAULT_DECOY_FILE = "vault_decoy.mvat"

_failed_attempts = 0
_last_failed_time = 0.0


def get_hardware_fingerprint() -> str:
    """Generates a hardware-bound SHA-256 fingerprint unique to this machine."""
    raw = f"{platform.node()}-{platform.machine()}-{os.environ.get('COMPUTERNAME', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def ensure_profiles_dir():
    """Ensures the profiles storage directory exists."""
    if not os.path.exists(PROFILES_DIR):
        os.makedirs(PROFILES_DIR, exist_ok=True)


def list_profiles() -> List[str]:
    """Lists all registered vault profile names."""
    ensure_profiles_dir()
    profiles = []
    
    # Check legacy root vault
    if os.path.exists(DEFAULT_VAULT_FILE):
        profiles.append("Varsayılan")

    for f in os.listdir(PROFILES_DIR):
        if f.endswith(".mvat") and not f.endswith("_decoy.mvat"):
            name = f[:-5]
            if name not in profiles:
                profiles.append(name)

    return profiles if profiles else ["Varsayılan"]


def get_profile_files(profile_name: str) -> Tuple[str, str]:
    """Returns filesystem paths for the real vault and decoy vault of a profile."""
    ensure_profiles_dir()
    if profile_name in ["Varsayılan", "Default"]:
        if os.path.exists(DEFAULT_VAULT_FILE):
            return DEFAULT_VAULT_FILE, DEFAULT_DECOY_FILE
        return os.path.join(PROFILES_DIR, "Varsayılan.mvat"), os.path.join(PROFILES_DIR, "Varsayılan_decoy.mvat")

    safe_name = "".join(c for c in profile_name if c.isalnum() or c in ("-", "_")).strip()
    if not safe_name:
        safe_name = "User"
    return os.path.join(PROFILES_DIR, f"{safe_name}.mvat"), os.path.join(PROFILES_DIR, f"{safe_name}_decoy.mvat")


def profile_exists(profile_name: str) -> bool:
    """Checks whether a given profile vault file exists on disk."""
    v_file, _ = get_profile_files(profile_name)
    return os.path.exists(v_file)


def generate_secure_password(length: int = 32, use_symbols: bool = True) -> str:
    """Generates a high-entropy CSPRNG password."""
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()-_=+"))

    for _ in range(length - len(password)):
        password.append(secrets.choice(characters))

    return "".join(password)


def init_vault(
    master_password: str,
    duress_password: Optional[str] = None,
    lang: str = "tr",
    profile_name: str = "Varsayılan",
    bind_to_hardware: bool = False
) -> Dict[str, Any]:
    """Initializes and encrypts a new user vault."""
    v_file, d_file = get_profile_files(profile_name)

    hw_id = get_hardware_fingerprint() if bind_to_hardware else None
    effective_password = (master_password + f"|HW:{hw_id}") if hw_id else master_password

    vault_data = {
        "version": 3,
        "profile_name": profile_name,
        "is_decoy": False,
        "hardware_bound": bind_to_hardware,
        "hardware_id": hw_id,
        "settings": {"language": lang},
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "items": [],
        "portfolio": [
            {
                "id": str(uuid.uuid4()),
                "coin": "BTC",
                "label": "Cold Storage 1 (Ledger)",
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "amount": 0.45,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        ]
    }
    save_vault(effective_password, vault_data, target_file=v_file)

    # Duress / Decoy Vault initialization
    if duress_password and duress_password.strip():
        eff_duress = (duress_password.strip() + f"|HW:{hw_id}") if hw_id else duress_password.strip()
        decoy_data = {
            "version": 3,
            "profile_name": profile_name,
            "is_decoy": True,
            "hardware_bound": bind_to_hardware,
            "settings": {"language": lang},
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "items": [
                {
                    "id": str(uuid.uuid4()),
                    "title": "Old Email Account",
                    "category": "User Password",
                    "secret": "MyNormalPass2022!",
                    "notes": "Low priority personal email",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            ],
            "portfolio": []
        }
        save_vault(eff_duress, decoy_data, target_file=d_file)

    return vault_data


def save_vault(password: str, vault_data: Dict[str, Any], target_file: Optional[str] = None, is_decoy: bool = False) -> None:
    """Encrypts and safely writes vault data to disk using atomic rename."""
    vault_data["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_json = json.dumps(vault_data, indent=2, ensure_ascii=False)
    armored = MilitaryVault.encrypt(raw_json, password)

    if not target_file:
        prof_name = vault_data.get("profile_name", "Varsayılan")
        v_file, d_file = get_profile_files(prof_name)
        target_file = d_file if is_decoy else v_file

    temp_file = target_file + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(armored)

    try:
        os.replace(temp_file, target_file)
    except OSError:
        if os.path.exists(target_file):
            os.remove(target_file)
        os.rename(temp_file, target_file)


def unlock_vault(password: str, profile_name: str = "Varsayılan") -> Tuple[Dict[str, Any], bool, str]:
    """
    Unlocks and decrypts the requested profile.
    Returns: (vault_data, is_decoy, effective_password)
    """
    global _failed_attempts, _last_failed_time

    # Anti-Brute-Force Rate Limiting
    if _failed_attempts >= 5:
        penalty = min(30, 2 ** (_failed_attempts - 4))
        elapsed = time.time() - _last_failed_time
        if elapsed < penalty:
            remaining = int(penalty - elapsed)
            raise VaultSecurityError(f"Too many failed unlock attempts! Wait {remaining} seconds (Anti-Brute Force).")

    v_file, d_file = get_profile_files(profile_name)

    if not os.path.exists(v_file):
        raise FileNotFoundError(f"Vault file for profile '{profile_name}' not found.")

    hw_id = get_hardware_fingerprint()
    candidate_passwords = [password, password + f"|HW:{hw_id}"]

    # 1. Attempt decryption of real vault (both standard and hardware-bound)
    with open(v_file, "r", encoding="utf-8") as f:
        armored = f.read()

    for cand in candidate_passwords:
        try:
            decrypted = MilitaryVault.decrypt(armored, cand)
            data = json.loads(decrypted.decode("utf-8"))
            data.setdefault("portfolio", [])
            data.setdefault("settings", {"language": "tr"})
            data.setdefault("profile_name", profile_name)
            _failed_attempts = 0
            return data, False, cand
        except VaultSecurityError:
            continue

    # 2. Attempt decryption of decoy vault (duress mode)
    if os.path.exists(d_file):
        with open(d_file, "r", encoding="utf-8") as f:
            armored_decoy = f.read()
        for cand in candidate_passwords:
            try:
                decrypted = MilitaryVault.decrypt(armored_decoy, cand)
                data_decoy = json.loads(decrypted.decode("utf-8"))
                data_decoy.setdefault("portfolio", [])
                data_decoy.setdefault("settings", {"language": "tr"})
                data_decoy.setdefault("profile_name", profile_name)
                _failed_attempts = 0
                return data_decoy, True, cand
            except VaultSecurityError:
                continue

    _failed_attempts += 1
    _last_failed_time = time.time()
    raise VaultSecurityError("Incorrect Master Password or Tampered Vault! (Hardware-locked vaults cannot open on other PCs).")


def add_secret_item(password: str, vault_data: Dict[str, Any], title: str, category: str, secret_value: str, notes: str = "") -> Dict[str, Any]:
    """Adds a new encrypted secret entry to the vault."""
    item = {
        "id": str(uuid.uuid4()),
        "title": title.strip(),
        "category": category,
        "secret": secret_value,
        "notes": notes.strip(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    vault_data["items"].insert(0, item)
    save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
    return item


def add_file_item(
    password: str,
    vault_data: Dict[str, Any],
    title: str,
    file_name: str,
    file_bytes: bytes,
    notes: str = ""
) -> Dict[str, Any]:
    """Encodes and embeds an arbitrary binary file (PDF, key, doc) inside the encrypted vault."""
    vault_data.setdefault("items", [])
    b64_str = base64.b64encode(file_bytes).decode("ascii")
    item = {
        "id": str(uuid.uuid4()),
        "title": title.strip() or file_name,
        "category": "Şifreli Dosya / Belge",
        "is_file": True,
        "file_name": file_name,
        "file_size": len(file_bytes),
        "file_b64": b64_str,
        "secret": f"[ENCRYPTED FILE]: {file_name} ({len(file_bytes):,} Bytes)",
        "notes": notes.strip(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    vault_data["items"].insert(0, item)
    save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
    return item


def delete_secret_item(password: str, vault_data: Dict[str, Any], item_id: str) -> bool:
    """Removes a secret or file entry from the vault by its UUID."""
    init_len = len(vault_data["items"])
    vault_data["items"] = [i for i in vault_data["items"] if i["id"] != item_id]
    if len(vault_data["items"]) < init_len:
        save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
        return True
    return False


def add_portfolio_item(password: str, vault_data: Dict[str, Any], coin: str, label: str, address: str, amount: float) -> Dict[str, Any]:
    """Adds a cold wallet address entry to the portfolio list."""
    vault_data.setdefault("portfolio", [])
    item = {
        "id": str(uuid.uuid4()),
        "coin": coin.upper(),
        "label": label.strip(),
        "address": address.strip(),
        "amount": amount,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    vault_data["portfolio"].insert(0, item)
    save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
    return item


def delete_portfolio_item(password: str, vault_data: Dict[str, Any], item_id: str) -> bool:
    """Deletes a portfolio address entry by its UUID."""
    vault_data.setdefault("portfolio", [])
    init_len = len(vault_data["portfolio"])
    vault_data["portfolio"] = [i for i in vault_data["portfolio"] if i["id"] != item_id]
    if len(vault_data["portfolio"]) < init_len:
        save_vault(password, vault_data, is_decoy=vault_data.get("is_decoy", False))
        return True
    return False
