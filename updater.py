"""
AegisVault GitHub Auto-Updater
GitHub Releases API üzerinden en güncel sürümü denetler ve otomatik güncelleme indirir.
"""

import json
import urllib.request
import os
import sys
import subprocess
from typing import Tuple, Optional, Dict, Any

CURRENT_VERSION = "3.5.0"
# Kullanıcı kendi GitHub reposunu buraya veya ayarlardan tanımlayabilir
DEFAULT_REPO = "user/AegisVault"


def check_for_github_update(repo_slug: str = DEFAULT_REPO) -> Tuple[bool, str, str, str]:
    """
    GitHub Releases API'sini sorgulayarak yeni sürüm olup olmadığını kontrol eder.
    
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
                body = data.get("body", "Yeni özellikler ve güvenlik yamaları.")
                
                download_url = ""
                for asset in data.get("assets", []):
                    name = asset.get("name", "").lower()
                    if name.endswith(".exe"):
                        download_url = asset.get("browser_download_url", "")
                        break

                if tag_name and tag_name > CURRENT_VERSION and download_url:
                    return True, tag_name, download_url, body
                return False, tag_name or CURRENT_VERSION, "", "Zaten en güncel sürümü kullanıyorsunuz."
    except Exception as e:
        return False, CURRENT_VERSION, "", f"GitHub kontrolü yapılamadı (Repo henüz public olmayabilir veya offline): {e}"

    return False, CURRENT_VERSION, "", "Güncelleme bulunamadı."


def apply_executable_update(download_url: str) -> bool:
    """
    Yeni AegisVault.exe dosyasını indirir ve mevcut çalışan uygulamanın yerine yazar.
    """
    try:
        temp_exe = "AegisVault_update.exe"
        req = urllib.request.Request(download_url, headers={"User-Agent": "AegisVault-Updater"})
        with urllib.request.urlopen(req, timeout=15.0) as resp, open(temp_exe, "wb") as f:
            f.write(resp.read())

        # Windows'ta çalışan dosya doğrudan üzerine yazılamayacağından küçük bir batch betiği çalıştırılır
        batch_script = """@echo off
timeout /t 2 /nobreak > nul
move /y AegisVault_update.exe AegisVault.exe
start AegisVault.exe
del "%~f0"
"""
        with open("update_installer.bat", "w") as f:
            f.write(batch_script)

        subprocess.Popen(["cmd.exe", "/c", "update_installer.bat"], creationflags=subprocess.CREATE_NO_WINDOW)
        sys.exit(0)
    except Exception as e:
        return False
