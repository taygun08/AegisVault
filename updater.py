"""
AegisVault GitHub Auto-Updater (Supply-Chain Hardened)
Queries GitHub Releases API over verified TLS to detect new releases,
enforces strict domain allowlisting, PE MZ header checks, and SHA-256 verification.
"""

import json
import urllib.request
import urllib.parse
import ssl
import hashlib
import os
import sys
import re
import subprocess
import webbrowser
from typing import Tuple, Optional, Dict, Any

CURRENT_VERSION = "3.5.4"
DEFAULT_REPO = "yiitpepek/AegisVault"
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


def parse_semver(version_str: str) -> Tuple[int, ...]:
    """Parses a version string into a comparable tuple of integers (e.g. 'v3.5.4' -> (3, 5, 4))."""
    clean = re.sub(r"[^\d.]", "", version_str.lstrip("v"))
    parts = []
    for p in clean.split("."):
        if p.isdigit():
            parts.append(int(p))
    return tuple(parts) if parts else (0,)


def _validate_repo_slug(repo_slug: str) -> str:
    """Prevents URL path injection by validating owner/repo format."""
    slug = repo_slug.strip()
    if not re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", slug):
        return DEFAULT_REPO
    return slug


def _is_trusted_https_url(url: str) -> bool:
    """Enforces HTTPS scheme and strict GitHub domain allowlist against SSRF/MITM."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != "https":
            return False
        host = (parsed.hostname or "").lower()
        return host in ALLOWED_DOWNLOAD_HOSTS or host.endswith(".githubusercontent.com")
    except Exception:
        return False


def open_github_releases_page(repo_slug: str = DEFAULT_REPO):
    """Opens the GitHub Releases creation/view page in the default web browser."""
    safe_slug = _validate_repo_slug(repo_slug)
    webbrowser.open(f"https://github.com/{safe_slug}/releases")


def check_for_github_update(repo_slug: str = DEFAULT_REPO) -> Tuple[bool, str, str, str]:
    """
    Check GitHub Releases API for a newer application version.
    
    Returns:
        (has_update: bool, latest_version: str, download_url: str, release_notes: str)
    """
    safe_slug = _validate_repo_slug(repo_slug)
    url = f"https://api.github.com/repos/{safe_slug}/releases/latest"
    tls_ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AegisVault-Updater"}
        )
        with urllib.request.urlopen(req, timeout=4.0, context=tls_ctx) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                tag_name = data.get("tag_name", "").lstrip("v")
                body = data.get("body", "New features and security patches.")
                
                download_url = ""
                for asset in data.get("assets", []):
                    name = asset.get("name", "").lower()
                    candidate_url = asset.get("browser_download_url", "")
                    if name.endswith(".exe") and _is_trusted_https_url(candidate_url):
                        download_url = candidate_url
                        break

                if tag_name and parse_semver(tag_name) > parse_semver(CURRENT_VERSION) and download_url:
                    return True, tag_name, download_url, body
                return False, tag_name or CURRENT_VERSION, "", f"En güncel sürümü kullanıyorsunuz (v{CURRENT_VERSION})."
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (
                False,
                CURRENT_VERSION,
                "",
                f"GitHub deponuz erişilebilir ancak henüz bir 'Release' (Sürüm) paketi yayınlanmadı.\n\nGitHub üzerinde 'Create a new release' butonuna basarak v{CURRENT_VERSION} etiketini ve derlenen AegisVault.exe dosyasını yayınlayabilirsiniz."
            )
        return False, CURRENT_VERSION, "", f"GitHub bağlantı hatası (HTTP {e.code}): {e.reason}"
    except Exception as e:
        return False, CURRENT_VERSION, "", f"GitHub kontrolü yapılamadı (Çevrimdışı veya ağ hatası): {e}"

    return False, CURRENT_VERSION, "", "Güncelleme bulunamadı."


def apply_executable_update(download_url: str, expected_sha256: Optional[str] = None) -> bool:
    """
    Download the updated AegisVault.exe over verified HTTPS, validate its Windows PE 'MZ'
    header and optional SHA-256 digest, and atomically replace the running binary.
    """
    if not _is_trusted_https_url(download_url):
        return False

    tls_ctx = ssl.create_default_context()
    try:
        temp_exe = "AegisVault_update.exe"
        req = urllib.request.Request(download_url, headers={"User-Agent": "AegisVault-Updater"})
        with urllib.request.urlopen(req, timeout=20.0, context=tls_ctx) as resp:
            if not _is_trusted_https_url(resp.geturl()):
                return False
            binary_data = resp.read()

        # Verify Windows PE executable signature ('MZ') and minimum binary size (1 MB)
        if len(binary_data) < 1024 * 1024 or not binary_data.startswith(b"MZ"):
            return False

        # Verify SHA-256 digest if provided
        actual_sha256 = hashlib.sha256(binary_data).hexdigest().lower()
        if expected_sha256 and actual_sha256 != expected_sha256.strip().lower():
            return False

        with open(temp_exe, "wb") as f:
            f.write(binary_data)

        # Determine target running executable name and sanitize against shell metacharacters
        if getattr(sys, 'frozen', False):
            target_exe = sys.executable
        else:
            target_exe = os.path.abspath("AegisVault.exe")

        raw_name = os.path.basename(target_exe)
        safe_target_name = re.sub(r'[^a-zA-Z0-9_.-]', '', raw_name) or "AegisVault.exe"

        batch_script = f"""@echo off
timeout /t 2 /nobreak > nul
move /y "{temp_exe}" "{safe_target_name}"
start "" "{safe_target_name}"
del "%~f0"
"""
        with open("update_installer.bat", "w", encoding="ascii") as f:
            f.write(batch_script)

        subprocess.Popen(["cmd.exe", "/c", "update_installer.bat"], creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)
    except Exception:
        return False

