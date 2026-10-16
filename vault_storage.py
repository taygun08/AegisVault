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
import hmac
import platform
import hashlib
import base64
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
from military_vault import MilitaryVault, VaultSecurityError

PROFILES_DIR = "profiles"
DEFAULT_VAULT_FILE = "vault_data.mvat"
DEFAULT_DECOY_FILE = "vault_decoy.mvat"
SECURITY_STATE_FILE = os.path.join(PROFILES_DIR, ".security_state.json")

_failed_attempts = 0
_last_failed_time = 0.0


def get_hardware_fingerprint() -> str:
    """Generates a hardware-bound SHA-256 fingerprint unique to this machine."""
    raw = f"{platform.node()}-{platform.machine()}-{os.environ.get('COMPUTERNAME', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def generate_keyfile(filepath: str) -> str:
    """
    Generates a high-entropy 512-bit (64-byte) CSPRNG 2FA cryptographic keyfile (.akey)
    for USB token / hardware two-factor authentication.
    Returns the 32-char SHA3-256 fingerprint of the keyfile.
    """
    raw_entropy = os.urandom(64)
    token_obj = {
        "header": "AEGIS-KEYFILE-2FA-v1",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "entropy_b64": base64.b64encode(raw_entropy).decode("ascii"),
        "checksum": hashlib.sha3_256(raw_entropy).hexdigest()
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(token_obj, f, indent=2)
    return compute_keyfile_digest(filepath)


def compute_keyfile_digest(filepath: str) -> str:
    """Computes a deterministic 256-bit SHA3-256 digest (32-hex prefix) of any 2FA keyfile."""
    if not filepath or not os.path.exists(filepath):
        raise VaultSecurityError("Selected 2FA Keyfile does not exist or USB drive is unplugged.")
    with open(filepath, "rb") as f:
        raw_bytes = f.read(50 * 1024 * 1024)  # Cap at 50 MB
    if not raw_bytes:
        raise VaultSecurityError("Selected 2FA Keyfile is empty.")
    return hashlib.sha3_256(raw_bytes).hexdigest()[:32]


def _load_security_state() -> Dict[str, Any]:
    """Loads the HMAC-authenticated persistent security state (Dead-Man's Switch & Brute-Force counters)."""
    ensure_profiles_dir()
    if not os.path.exists(SECURITY_STATE_FILE):
        return {"profiles": {}}
    try:
        with open(SECURITY_STATE_FILE, "r", encoding="utf-8") as f:
            wrapper = json.load(f)
        state = wrapper.get("state", {"profiles": {}})
        tag = wrapper.get("hmac", "")
        hw_key = f"AEGIS-STATE-HMAC:{get_hardware_fingerprint()}".encode("utf-8")
        expected = hmac.new(hw_key, json.dumps(state, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(tag, expected):
            try:
                from military_audit import CryptographicAuditTrail
                CryptographicAuditTrail.record_event(
                    "SECURITY_STATE_TAMPER",
                    "SYSTEM",
                    "HMAC mismatch on .security_state.json detected.",
                    "CRITICAL"
                )
            except Exception:
                pass
        return state
    except Exception:
        return {"profiles": {}}


def _save_security_state(state: Dict[str, Any]) -> None:
    """Saves the persistent security state sealed with a hardware-bound HMAC-SHA256 tag."""
    ensure_profiles_dir()
    hw_key = f"AEGIS-STATE-HMAC:{get_hardware_fingerprint()}".encode("utf-8")
    tag = hmac.new(hw_key, json.dumps(state, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
    wrapper = {"state": state, "hmac": tag}
    tmp = SECURITY_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(wrapper, f, indent=2)
    try:
        os.replace(tmp, SECURITY_STATE_FILE)
    except OSError:
        if os.path.exists(SECURITY_STATE_FILE):
            os.remove(SECURITY_STATE_FILE)
        os.rename(tmp, SECURITY_STATE_FILE)


def get_profile_security_policy(profile_name: str) -> Dict[str, Any]:
    """Returns the Dead-Man's Switch & Brute-Force policy for a given profile."""
    state = _load_security_state()
    prof = state.setdefault("profiles", {}).get(profile_name, {})
    return {
        "dms_days": int(prof.get("dms_days", 0)),
        "max_failed_wipe": int(prof.get("max_failed_wipe", 0)),
        "failed_attempts": int(prof.get("failed_attempts", 0)),
        "last_checkin_epoch": float(prof.get("last_checkin_epoch", time.time())),
    }


def configure_profile_security_policy(profile_name: str, dms_days: int, max_failed_wipe: int) -> None:
    """Updates Dead-Man's Switch (inactivity days) and Scorched-Earth Brute-Force Wipe threshold."""
    state = _load_security_state()
    prof = state.setdefault("profiles", {}).setdefault(profile_name, {})
    prof["dms_days"] = max(0, int(dms_days))
    prof["max_failed_wipe"] = max(0, int(max_failed_wipe))
    prof["last_checkin_epoch"] = time.time()
    _save_security_state(state)
    try:
        from military_audit import CryptographicAuditTrail
        CryptographicAuditTrail.record_event(
            "SECURITY_POLICY_UPDATE",
            profile_name,
            f"Dead-Man's Switch={dms_days}d | Scorched-Earth Brute-Force Limit={max_failed_wipe}",
            "INFO"
        )
    except Exception:
        pass


def check_dead_mans_switch(profile_name: str) -> Tuple[bool, str]:
    """
    Evaluates whether the Dead-Man's Switch inactivity timer has expired for a profile.
    If expired, automatically executes DoD 5220.22-M 3-pass cryptographic zeroization.
    Returns: (triggered: bool, message: str)
    """
    state = _load_security_state()
    prof = state.get("profiles", {}).get(profile_name, {})
    dms_days = int(prof.get("dms_days", 0))
    last_checkin = float(prof.get("last_checkin_epoch", 0))

    if dms_days > 0 and last_checkin > 0:
        elapsed_days = (time.time() - last_checkin) / 86400.0
        if elapsed_days >= dms_days:
            v_file, _ = get_profile_files(profile_name)
            if os.path.exists(v_file):
                from military_audit import emergency_zeroize_vault, CryptographicAuditTrail
                emergency_zeroize_vault(profile_name)
                CryptographicAuditTrail.record_event(
                    "DEAD_MANS_SWITCH_TRIGGERED",
                    profile_name,
                    f"Inactivity threshold ({dms_days} days) exceeded. Vault automatically zeroized.",
                    "CRITICAL"
                )
                prof["dms_days"] = 0
                _save_security_state(state)
                return True, f"DEAD-MAN'S SWITCH TRIGGERED: Profile '{profile_name}' exceeded {dms_days} days of inactivity and was cryptographically shredded (DoD 5220.22-M)."
    return False, ""


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
    bind_to_hardware: bool = False,
    keyfile_path: Optional[str] = None
) -> Dict[str, Any]:
    """Initializes and encrypts a new user vault with optional Hardware Binding and 2FA Keyfile."""
    v_file, d_file = get_profile_files(profile_name)

    hw_id = get_hardware_fingerprint() if bind_to_hardware else None
    kf_id = compute_keyfile_digest(keyfile_path) if (keyfile_path and keyfile_path.strip()) else None

    effective_password = master_password
    if hw_id:
        effective_password += f"|HW:{hw_id}"
    if kf_id:
        effective_password += f"|KF:{kf_id}"

    vault_data = {
        "version": 3,
        "profile_name": profile_name,
        "is_decoy": False,
        "hardware_bound": bind_to_hardware,
        "hardware_id": hw_id,
        "keyfile_bound": bool(kf_id),
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

    # Record initial Dead-Man's Switch check-in
    state = _load_security_state()
    prof_state = state.setdefault("profiles", {}).setdefault(profile_name, {})
    prof_state["last_checkin_epoch"] = time.time()
    prof_state["failed_attempts"] = 0
    _save_security_state(state)

    # Duress / Decoy Vault initialization
    if duress_password and duress_password.strip():
        eff_duress = duress_password.strip()
        if hw_id:
            eff_duress += f"|HW:{hw_id}"
        if kf_id:
            eff_duress += f"|KF:{kf_id}"
        decoy_data = {
            "version": 3,
            "profile_name": profile_name,
            "is_decoy": True,
            "hardware_bound": bind_to_hardware,
            "keyfile_bound": bool(kf_id),
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


def unlock_vault(
    password: str,
    profile_name: str = "Varsayılan",
    keyfile_path: Optional[str] = None
) -> Tuple[Dict[str, Any], bool, str]:
    """
    Unlocks and decrypts the requested profile. Enforces Dead-Man's Switch,
    persistent Anti-Brute-Force backoff, Scorched-Earth Wipe threshold, and 2FA Keyfile.
    Returns: (vault_data, is_decoy, effective_password)
    """
    global _failed_attempts, _last_failed_time

    # 0. Check Dead-Man's Switch Inactivity Timer prior to unlock
    dms_triggered, dms_msg = check_dead_mans_switch(profile_name)
    if dms_triggered:
        raise VaultSecurityError(dms_msg)

    state = _load_security_state()
    prof_state = state.setdefault("profiles", {}).setdefault(profile_name, {})
    persisted_fails = max(_failed_attempts, int(prof_state.get("failed_attempts", 0)))
    last_fail_ts = max(_last_failed_time, float(prof_state.get("last_failed_time", 0.0)))

    # 1. Anti-Brute-Force Exponential Rate Limiting (Persists across restarts)
    if persisted_fails >= 5:
        penalty = min(60, 2 ** min(10, persisted_fails - 4))
        elapsed = time.time() - last_fail_ts
        if elapsed < penalty:
            remaining = int(penalty - elapsed) + 1
            raise VaultSecurityError(f"Too many failed unlock attempts ({persisted_fails})! Wait {remaining} seconds (Anti-Brute Force).")

    v_file, d_file = get_profile_files(profile_name)

    if not os.path.exists(v_file):
        raise FileNotFoundError(f"Vault file for profile '{profile_name}' not found.")

    hw_id = get_hardware_fingerprint()
    kf_id = compute_keyfile_digest(keyfile_path) if (keyfile_path and keyfile_path.strip()) else None

    base_candidates = [password, f"{password}|HW:{hw_id}"]
    if kf_id:
        candidate_passwords = [f"{c}|KF:{kf_id}" for c in base_candidates] + base_candidates
    else:
        candidate_passwords = base_candidates

    # 2. Attempt decryption of real vault
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
            prof_state["failed_attempts"] = 0
            prof_state["last_checkin_epoch"] = time.time()
            _save_security_state(state)
            return data, False, cand
        except VaultSecurityError:
            continue

    # 3. Attempt decryption of decoy vault (duress mode)
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
                prof_state["failed_attempts"] = 0
                _save_security_state(state)
                return data_decoy, True, cand
            except VaultSecurityError:
                continue

    # 4. Handle Authentication Failure & Scorched-Earth Brute-Force Self-Destruct
    _failed_attempts = persisted_fails + 1
    _last_failed_time = time.time()
    prof_state["failed_attempts"] = _failed_attempts
    prof_state["last_failed_time"] = _last_failed_time
    _save_security_state(state)

    max_wipe = int(prof_state.get("max_failed_wipe", 0))
    if max_wipe > 0 and _failed_attempts >= max_wipe:
        from military_audit import emergency_zeroize_vault, CryptographicAuditTrail
        emergency_zeroize_vault(profile_name)
        CryptographicAuditTrail.record_event(
            "SCORCHED_EARTH_BRUTEFORCE_WIPE",
            profile_name,
            f"Failed attempts ({_failed_attempts}) reached Scorched-Earth limit ({max_wipe}). Vault shredded.",
            "CRITICAL"
        )
        prof_state["failed_attempts"] = 0
        _save_security_state(state)
        raise VaultSecurityError(
            f"SCORCHED-EARTH PROTOCOL TRIGGERED: {_failed_attempts}/{max_wipe} failed attempts reached. Vault cryptographically zeroized (DoD 5220.22-M)."
        )

    raise VaultSecurityError("Incorrect Master Password, Missing 2FA Keyfile, or Hardware Mismatch!")


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
    safe_fname = os.path.basename(file_name).replace("\x00", "").strip() or "document.bin"
    b64_str = base64.b64encode(file_bytes).decode("ascii")
    item = {
        "id": str(uuid.uuid4()),
        "title": title.strip() or safe_fname,
        "category": "Şifreli Dosya / Belge",
        "is_file": True,
        "file_name": safe_fname,
        "file_size": len(file_bytes),
        "file_b64": b64_str,
        "secret": f"[ENCRYPTED FILE]: {safe_fname} ({len(file_bytes):,} Bytes)",
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
