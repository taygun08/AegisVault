"""
AegisVault GitHub Auto-Updater
Queries GitHub Releases API to detect new releases and download updates.
"""

import json
import urllib.request
import os
import sys
import subprocess
import webbrowser
from typing import Tuple, Optional, Dict, Any

CURRENT_VERSION = "3.5.4"
# Default GitHub repository slug
DEFAULT_REPO = "yiitpepek/AegisVault"


import re


def parse_semver(version_str: str) -> Tuple[int, ...]:
    """Parses a version string into a comparable tuple of integers (e.g. 'v3.5.4' -> (3, 5, 4))."""
    clean = re.sub(r"[^\d.]", "", version_str.lstrip("v"))
    parts = []
    for p in clean.split("."):
        if p.isdigit():
            parts.append(int(p))
    return tuple(parts) if parts else (0,)


def open_github_releases_page(repo_slug: str = DEFAULT_REPO):
    """Opens the GitHub Releases creation/view page in the default web browser."""
    webbrowser.open(f"https://github.com/{repo_slug}/releases")


def check_for_github_update(repo_slug: str = DEFAULT_REPO) -> Tuple[bool, str, str, str]:
    """
    Check GitHub Releases API for a newer application version.
    
    Returns:
        (has_update: bool, latest_version: str, download_url: str, release_notes: str)
    """
    url = f"https://api.github.com/repos/{repo_slug}/releases/latest"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AegisVault-Updater"}
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                tag_name = data.get("tag_name", "").lstrip("v")
                body = data.get("body", "New features and security patches.")
                
                download_url = ""
                for asset in data.get("assets", []):
                    name = asset.get("name", "").lower()
                    if name.endswith(".exe"):
                        download_url = asset.get("browser_download_url", "")
                        break

                if tag_name and parse_semver(tag_name) > parse_semver(CURRENT_VERSION) and download_url:
                    return True, tag_name, download_url, body
                return False, tag_name or CURRENT_VERSION, "", f"En güncel sürümü kullanıyorsunuz (v{CURRENT_VERSION})."
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # 404 on /releases/latest means no release has been published yet
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


def apply_executable_update(download_url: str) -> bool:
    """
    Download the updated AegisVault.exe and replace the currently running binary.
    """
    try:
        temp_exe = "AegisVault_update.exe"
        req = urllib.request.Request(download_url, headers={"User-Agent": "AegisVault-Updater"})
        with urllib.request.urlopen(req, timeout=15.0) as resp, open(temp_exe, "wb") as f:
            f.write(resp.read())

        # Determine target running executable name and path
        if getattr(sys, 'frozen', False):
            target_exe = sys.executable
        else:
            target_exe = os.path.abspath("AegisVault.exe")

        target_name = os.path.basename(target_exe)

        # On Windows, replace the active executable using a background launcher script
        batch_script = f"""@echo off
timeout /t 2 /nobreak > nul
move /y "{temp_exe}" "{target_name}"
start "" "{target_name}"
del "%~f0"
"""
        with open("update_installer.bat", "w", encoding="ascii") as f:
            f.write(batch_script)

        subprocess.Popen(["cmd.exe", "/c", "update_installer.bat"], creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)
    except Exception:
        return False
