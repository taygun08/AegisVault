# 🛡️ AegisVault 3.5 — Military-Grade Cold Storage & P2P Cryptographic Suite

![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)
![Security](https://img.shields.io/badge/Security-AES--256--GCM-brightgreen.svg)
![KDF](https://img.shields.io/badge/KDF-scrypt%20(BIP--38)-orange.svg)
![P2P](https://img.shields.io/badge/Network-P2P%20Encrypted%20Socket-purple.svg)

**AegisVault** is an enterprise & military-grade offline cryptographic vault, cold-storage cryptocurrency manager, and serverless peer-to-peer (P2P) encrypted messenger. Built in accordance with **NSA CNSA Suite** and **Bitcoin BIP-38 / BIP-39** standards.

---

## 🚀 Key Features

* **🔑 Military Core Encryption:** AES-256-GCM authenticated symmetric encryption with 96-bit CSPRNG nonces and Associated Authenticated Data (AAD) preventing bit-flip tampering.
* **🔒 Memory-Hard KDF (`scrypt`):** $N=32768, r=8, p=1$ memory-hard cost parameter rendering GPU/ASIC cluster brute-force attacks mathematically and economically infeasible.
* **👤 Multi-User Profiles:** Independent profiles and password vaults for different users or computers (`profiles/<user>.mvat`).
* **💻 Hardware Fingerprint Binding:** Optional machine-binding locking the vault exclusively to the physical CPU/Motherboard where it was created.
* **💬 Live P2P Encrypted Chat:** Direct computer-to-computer serverless messaging over encrypted sockets with AES-256-GCM frame protection.
* **📊 Watch-Only Blockchain Portfolio:** Real-time Bitcoin balance querying directly from `blockchain.info` public nodes and live price tracking (BTC, ETH, SOL) via Binance API.
* **🧩 Shamir's Secret Sharing (SSS):** $K$-of-$N$ threshold secret sharing over prime field $\mathbb{F}_{257}$ for paper seed backups (e.g., 3-of-5 threshold).
* **🎭 Plausible Deniability (Duress Mode):** Secondary duress password opens an innocuous decoy vault under coercion.
* **⏱️ Inactivity Auto-Lock:** Wipes RAM keys and auto-locks after 120 seconds of user inactivity.
* **🛡️ FIPS 140-3 Power-On Self-Tests (POST):** Automated boot-up verification with official NIST SP 800-38D Known-Answer Tests (KAT) for AES-256-GCM, scrypt KDF, and CSPRNG continuous health.
* **📜 Tamper-Evident Hash-Chained Audit Trail:** Blockchain-like cryptographic event log chaining every action with SHA-256 hashes to guarantee mathematical audit integrity.
* **⏱️ Burn-After-Reading Ephemeral Messaging:** Self-destructing tactical intelligence messages automatically purged from memory and display after 30 seconds.
* **📎 Tactical Encrypted File Drop:** End-to-end AES-256-GCM document/image/payload transfer over decentralized real-time relay channels.
* **📁 Encrypted File Locker (Vault):** Store and protect confidential files (PDF, Office, keys, maps) with AES-256-GCM inside the encrypted user vault.
* **📲 Air-Gapped Optical QR Communication:** Optical data transfer for classified and network-isolated environments (no Wi-Fi, no Bluetooth, no cables) using encrypted dynamic QR codes and OpenCV machine vision decoding.
* **🌐 Multilingual:** Full localization in 🇹🇷 Türkçe, 🇬🇧 English, and 🇷🇺 Русский.

---

## 📦 Installation & Usage

### 1. Direct Executable (Windows)
Run `AegisVault.exe` directly without installing Python:
```cmd
AegisVault.exe
```

### 2. From Source
```bash
git clone https://github.com/<your-username>/AegisVault.git
cd AegisVault
pip install -r requirements.txt
python app.py
```

### 3. Build Standalone `.exe`
```powershell
pip install pyinstaller customtkinter cryptography
pyinstaller --noconsole --onefile --name "AegisVault" --collect-all customtkinter app.py
```

---

## 🔒 Security Architecture

| Layer | Standard / Implementation | Purpose |
| :--- | :--- | :--- |
| **Symmetric Cipher** | AES-256-GCM (NIST SP 800-38D) | Confidentiality & Authenticity |
| **Key Derivation** | scrypt (BIP-38 Standard) | GPU/ASIC Brute-Force Defense |
| **Integrity Tag** | 128-bit GHASH in $\mathbb{F}_{2^{128}}$ | Anti-Tamper / Bit-flip Detection |
| **Secret Sharing** | Lagrange Polynomials in $\mathbb{F}_{257}$ | Information-Theoretic Backup |
| **Entropy** | OS CSPRNG (`os.urandom`) | Unpredictable Nonce & Salt |

---

## 📄 License
MIT License. Open-source for educational and cold-storage security use.
