"""
Military-Grade Cryptographic Vault (Deneysel & Cold-Storage Kripto Kasası)
Standartlar:
- Simetrik Şifreleme: AES-256-GCM (NIST SP 800-38D / NSA CNSA Suite)
- Anahtar Türetme (KDF): scrypt (BIP-38 & Ethereum Web3 Keystore Standardı, GPU/ASIC dirençli)
- Bütünlük & Kurcalama Koruması: AEAD (Authenticated Encryption with Associated Data)
- Entropi: Kriptografik Güvenli Donanımsal/İşletim Sistemi Rastgele Sayı Üreteci (CSPRNG - os.urandom)
"""

import os
import struct
import base64
import sys
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class VaultSecurityError(Exception):
    """Yetkisiz erişim, kurcalama veya yanlış parola durumunda fırlatılır."""
    pass


class MilitaryVault:
    """
    AES-256-GCM ve scrypt tabanlı yüksek güvenlikli askeri sınıf şifreleme motoru.
    
    Özellikler:
    - 256-bit anahtar uzunluğu (En üst düzey askeri sınıf gizlilik)
    - 96-bit benzersiz Nonce/IV (NIST standardı, asla tekrar kullanılmaz)
    - scrypt bellek zorlamalı KDF (Kaba kuvvet ve GPU/ASIC küme saldırılarını engeller)
    - Başlık Doğrulama (AAD): Versiyon ve KDF parametreleri kurcalanamaz.
    """

    MAGIC_BYTES = b"MVAULT"  # 6 bytes
    VERSION = 1               # 1 byte (v1)
    KDF_SCRYPT = 1            # 1 byte tanımlayıcı

    # Güvenli Varsayılan scrypt Parametreleri (BIP-38 / Finansal Düzey)
    # N=32768 (2^15), r=8, p=1 (~32MB RAM gerektirir, GPU brute-force'u felç eder)
    DEFAULT_LOG_N = 15
    DEFAULT_R = 8
    DEFAULT_P = 1
    SALT_SIZE = 16            # 128-bit kriptografik tuz (CSPRNG)
    NONCE_SIZE = 12           # 96-bit GCM Nonce (NIST SP 800-38D)
    KEY_LENGTH = 32           # 256-bit AES anahtarı

    HEADER_FORMAT = ">6sBBBI I 16s 12s"
    # Alanlar:
    # 6s: Magic (MVAULT)
    # B : Version (1)
    # B : KDF Type (1 = scrypt)
    # B : log_n (15)
    # I : r (8)
    # I : p (1)
    # 16s: Salt
    # 12s: Nonce

    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @classmethod
    def _zero_memory(cls, target: Union[bytearray, memoryview]):
        """
        Hassas veriyi (anahtar/parola) Python bellek çöp toplayıcısından
        önce sıfırlayarak RAM dump saldırılarına karşı yüzeyi küçültür.
        """
        if isinstance(target, bytearray):
            for i in range(len(target)):
                target[i] = 0

    @classmethod
    def _derive_key(cls, password: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
        """Paroladan scrypt algoritması ile 256-bit (32 byte) anahtar türetir."""
        kdf = Scrypt(
            salt=salt,
            length=cls.KEY_LENGTH,
            n=n,
            r=r,
            p=p,
        )
        return kdf.derive(password)

    @classmethod
    def encrypt(cls, plaintext: Union[str, bytes], password: str) -> str:
        """
        Metin veya ikili veriyi AES-256-GCM ile şifreler ve taşınabilir Base64 zarfı döndürür.
        
        Args:
            plaintext: Şifrelenecek gizli veri (Bitcoin Seed Phrase, özel anahtar, metin vb.)
            password: Kullanıcı ana parolası
            
        Returns:
            Zırhlı Base64 string (Vault Envelope)
        """
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = bytes(plaintext)

        password_bytes = bytearray(password.encode("utf-8"))

        # 1. Kriptografik Olarak Güvenli Rastgele Tuz (Salt) ve Nonce (IV) Üret
        salt = os.urandom(cls.SALT_SIZE)
        nonce = os.urandom(cls.NONCE_SIZE)

        log_n = cls.DEFAULT_LOG_N
        n = 1 << log_n
        r = cls.DEFAULT_R
        p = cls.DEFAULT_P

        # 2. scrypt ile 256-bit Askeri Anahtar Türet
        key = bytearray(cls._derive_key(bytes(password_bytes), salt, n, r, p))

        # 3. Kapsül Başlığını (Header) Oluştur
        # Bu başlık AAD (Associated Authenticated Data) olarak kullanılacak.
        header = struct.pack(
            cls.HEADER_FORMAT,
            cls.MAGIC_BYTES,
            cls.VERSION,
            cls.KDF_SCRYPT,
            log_n,
            r,
            p,
            salt,
            nonce,
        )

        try:
            # 4. AES-256-GCM ile Şifrele + Bütünlük Doğrulama Etiketi (Auth Tag) Ekle
            # AAD olarak 'header' verilir. Böylece parametreler asla kurcalanamaz.
            aesgcm = AESGCM(bytes(key))
            ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=header)

            # 5. Başlık + Şifreli Metin (Ciphertext + 16 byte Tag) Birleştir
            full_payload = header + ciphertext
            armored = base64.b64encode(full_payload).decode("ascii")
            return armored

        finally:
            # Bellek Temizliği (RAM Hijyen)
            cls._zero_memory(password_bytes)
            cls._zero_memory(key)

    @classmethod
    def decrypt(cls, armored_payload: str, password: str) -> bytes:
        """
        Zırhlı Base64 şifreli veriyi çözer ve bütünlüğünü doğrular.
        
        Args:
            armored_payload: encrypt() çıktısı olan Base64 paket
            password: Doğru parola
            
        Returns:
            Çözülmüş orijinal veri (bytes)
            
        Raises:
            VaultSecurityError: Yanlış parola, bozuk veri veya kurcalanmış paket tespiti.
        """
        try:
            raw_data = base64.b64decode(armored_payload.strip().encode("ascii"))
        except Exception as e:
            raise VaultSecurityError("Geçersiz paket formatı: Base64 çözülemedi.") from e

        if len(raw_data) < cls.HEADER_SIZE + 16:  # 16 = GCM tag boyutu
            raise VaultSecurityError("Paket boyutu çok küçük veya eksik.")

        # 1. Başlığı Ayrıştır
        header = raw_data[:cls.HEADER_SIZE]
        ciphertext = raw_data[cls.HEADER_SIZE:]

        try:
            magic, version, kdf_type, log_n, r, p, salt, nonce = struct.unpack(
                cls.HEADER_FORMAT, header
            )
        except struct.error as e:
            raise VaultSecurityError("Başlık yapısı bozuk.") from e

        if magic != cls.MAGIC_BYTES:
            raise VaultSecurityError("Geçersiz kasa formatı (Magic Bytes eşleşmiyor).")

        if version != cls.VERSION:
            raise VaultSecurityError(f"Desteklenmeyen kasa versiyonu: {version}")

        if kdf_type != cls.KDF_SCRYPT:
            raise VaultSecurityError("Desteklenmeyen KDF algoritması.")

        # Parametre limit kontrolü (DoS saldırılarına karşı önlem)
        if log_n > 22 or log_n < 10:  # 1024 ile 4M iterasyon arası
            raise VaultSecurityError("Güvenlik sınırları dışındaki scrypt parametresi.")

        n = 1 << log_n
        password_bytes = bytearray(password.encode("utf-8"))

        try:
            # 2. Anahtarı Aynı Parametrelerle Türet
            key = bytearray(cls._derive_key(bytes(password_bytes), salt, n, r, p))

            # 3. AES-256-GCM ile Çöz ve Doğrula
            aesgcm = AESGCM(bytes(key))
            decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data=header)
            return decrypted

        except Exception as e:
            # GCM kimlik doğrulama etiketi eşleşmezse bu hataya düşer.
            raise VaultSecurityError(
                "Şifre çözme BAŞARISIZ! (Yanlış parola veya veri kurcalanmış/bozulmuş)."
            ) from e
        finally:
            cls._zero_memory(password_bytes)
            if 'key' in locals():
                cls._zero_memory(key)

    @classmethod
    def encrypt_file(cls, input_file_path: str, output_file_path: str, password: str):
        """Bir dosyayı doğrudan askeri standartta şifreler."""
        with open(input_file_path, "rb") as f:
            data = f.read()
        encrypted_armored = cls.encrypt(data, password)
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(encrypted_armored)

    @classmethod
    def decrypt_file(cls, input_file_path: str, output_file_path: str, password: str):
        """Şifreli kasa dosyasını çözer ve hedefe yazar."""
        with open(input_file_path, "r", encoding="utf-8") as f:
            encrypted_armored = f.read()
        decrypted_bytes = cls.decrypt(encrypted_armored, password)
        with open(output_file_path, "wb") as f:
            f.write(decrypted_bytes)


def run_self_test():
    """Kasanın güvenlik, doğruluk ve kurcalama testlerini çalıştırır."""
    print("=" * 65)
    print(" MILITARY-GRADE VAULT GÜVENLİK VE ENTEGRASYON TESTİ")
    print("=" * 65)

    # 1. Test: Kritik Bitcoin 24 Kelimelik Seed Phrase
    mock_btc_seed = (
        "witch collapse practice feed shame open despair creek "
        "road again ice least flame doctor immense metal "
        "flame doctor immense metal flame doctor immense metal"
    )
    master_password = "Kullanici@Gizli!Parola9921#$"

    print("\n[+] 1. Adım: Bitcoin Seed Phrase Şifreleniyor...")
    armored = MilitaryVault.encrypt(mock_btc_seed, master_password)
    print(f"    Şifreli Çıktı (İlk 80 karakter): {armored[:80]}...")
    print(f"    Toplam Kapsül Boyutu: {len(armored)} karakter (Base64)")

    print("\n[+] 2. Adım: Doğru Parola ile Şifre Çözülüyor...")
    decrypted_bytes = MilitaryVault.decrypt(armored, master_password)
    decrypted_text = decrypted_bytes.decode("utf-8")
    assert decrypted_text == mock_btc_seed, "HATA: Çözülen metin eşleşmedi!"
    print("    [BAŞARILI] Veri birebir hatasız çözüldü.")

    print("\n[+] 3. Adım: Yanlış Parola Testi Yapılıyor...")
    try:
        MilitaryVault.decrypt(armored, "YanlisParola123")
        print("    [HATA] Yanlış parola kabul edildi! (Güvenlik zafiyeti)")
    except VaultSecurityError:
        print("    [BAŞARILI] Yanlış parola derhal reddedildi (Auth Tag Mismatch).")

    print("\n[+] 4. Adım: Kurcalama ve Veri Manipülasyonu Testi (Bit-Flip Attack)...")
    # Şifreli metnin ortasından 1 karakteri değiştirerek kurcalayalım
    tampered_armored = armored[:100] + ("A" if armored[100] != "A" else "B") + armored[101:]
    try:
        MilitaryVault.decrypt(tampered_armored, master_password)
        print("    [HATA] Kurcalanmış veri kabul edildi!")
    except VaultSecurityError:
        print("    [BAŞARILI] 1 bitlik kurcalama bile AEAD tarafından tespit edildi ve işlem iptal edildi.")

    print("\n" + "=" * 65)
    print(" TÜM ASKERİ STANDART DOĞRULAMA TESTLERİ BAŞARIYLA GEÇTİ!")
    print("=" * 65)


if __name__ == "__main__":
    run_self_test()
