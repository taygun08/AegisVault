"""
Live P2P Encrypted Chat Network (Doğrudan İki Bilgisayar Arası Şifreli Sohbet)
Özellikler:
- P2P Socket Sunucu / İstemci (Sunucusuz, Doğrudan Bağlantı)
- Her mesaj paketi AES-256-GCM ile zırhlanır
- Otomatik Yerel IP Tespiti
- Karşılıklı Gerçek Zamanlı Mesajlaşma (Telegram / Signal Tarzı)
"""

import socket
import threading
import time
from datetime import datetime
from typing import Callable, Optional, List
import crypto_chat


def get_local_ip() -> str:
    """Makinanın yerel IP adresini tespit eder."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class P2PChatSession:
    """Hem Host (Oda Sahibi) hem Client (Katılımcı) için ortak P2P motoru."""

    def __init__(self, username: str, room_key: str, on_message: Callable, on_status: Callable):
        self.username = username
        self.room_key = room_key
        self.on_message = on_message
        self.on_status = on_status

        self.server_sock: Optional[socket.socket] = None
        self.conn: Optional[socket.socket] = None
        self.is_running = False
        self.is_host = False

    def start_host(self, port: int = 9876):
        """Oda kurucu olarak dinlemeye başlar."""
        self.is_host = True
        self.is_running = True

        def listen_worker():
            try:
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind(("0.0.0.0", port))
                self.server_sock.listen(1)
                local_ip = get_local_ip()
                self.on_status(f"🟢 Oda Açıldı! IP: {local_ip}:{port} | Bağlantı bekleniyor...")

                self.conn, addr = self.server_sock.accept()
                self.on_status(f"✅ Karşı taraf bağlandı ({addr[0]})! Sohbet şifreli ve aktif.")
                self._receive_loop()
            except Exception as e:
                if self.is_running:
                    self.on_status(f"❌ Bağlantı hatası: {e}")

        threading.Thread(target=listen_worker, daemon=True).start()

    def connect_to_host(self, host_ip: str, port: int = 9876):
        """Var olan bir odaya katılır."""
        self.is_host = False
        self.is_running = True

        def connect_worker():
            try:
                self.on_status(f"🟡 {host_ip}:{port} adresine bağlanılıyor...")
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((host_ip, port))
                self.on_status(f"✅ Odaya bağlanıldı! AES-256-GCM şifreleme devrede.")
                self._receive_loop()
            except Exception as e:
                self.on_status(f"❌ Bağlantı kurulamadı: {e}")

        threading.Thread(target=connect_worker, daemon=True).start()

    def _receive_loop(self):
        """Gelen şifreli mesajları dinler ve çözer."""
        while self.is_running and self.conn:
            try:
                raw_data = self.conn.recv(8192)
                if not raw_data:
                    break
                token = raw_data.decode("utf-8").strip()
                if not token:
                    continue

                try:
                    payload = crypto_chat.decrypt_message(token, self.room_key)
                    # payload: {"text": "sender:msg", "timestamp": "..."}
                    full_text = payload.get("text", "")
                    ts = payload.get("timestamp", datetime.now().strftime("%H:%M:%S"))

                    sender = "Karşı Taraf"
                    body = full_text
                    if ": " in full_text:
                        parts = full_text.split(": ", 1)
                        sender = parts[0]
                        body = parts[1]

                    self.on_message(sender, body, ts, is_mine=False)
                except Exception:
                    self.on_status("⚠️ Şifresi çözülemeyen paket alındı (Oda anahtarı uyuşmuyor olabilir).")
            except Exception:
                break

        self.on_status("🔴 Sohbet bağlantısı kesildi.")
        self.close()

    def send_message(self, text: str) -> bool:
        """Mesajı zırhlayıp karşı tarafa gönderir."""
        if not self.conn:
            return False

        try:
            formatted = f"{self.username}: {text}"
            token = crypto_chat.encrypt_message(formatted, self.room_key)
            self.conn.sendall((token + "\n").encode("utf-8"))
            ts = datetime.now().strftime("%H:%M:%S")
            self.on_message(self.username, text, ts, is_mine=True)
            return True
        except Exception:
            return False

    def close(self):
        self.is_running = False
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
