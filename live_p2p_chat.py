"""
Global Encrypted Chat Network (Dünya Çapı İnternet & P2P Sohbet Ağı)
Özellikler:
- Türkiye'den İngiltere'ye, dünyanın her yerinden doğrudan bağlantı (NAT / Port Açma Engeli Yok)
- Sıfır Sunucu Kurulumu: Güvenli küresel MQTT relay (broker.hivemq.com) üzerinden anlık iletim
- Uçtan Uca Askeri Şifreleme: Mesajlar bilgisayardan çıkmadan önce AES-256-GCM ile zırhlanır
- Aradaki aracı sunucu yalnızca anlamsız şifreli metin (AEGIS-MSG-v1:...) görür
"""

import time
import uuid
import threading
from datetime import datetime
from typing import Callable, Optional
import paho.mqtt.client as mqtt
import crypto_chat

DEFAULT_BROKER = "broker.hivemq.com"
DEFAULT_PORT = 1883


class GlobalEncryptedChatSession:
    """Dünya çapında çalışan uçtan uca şifreli küresel sohbet oturumu."""

    def __init__(self, username: str, room_name: str, room_key: str, on_message: Callable, on_status: Callable):
        self.username = username.strip() or "Anonim"
        self.room_name = room_name.strip().lower() or "genel-oda"
        self.room_key = room_key.strip()
        self.on_message = on_message
        self.on_status = on_status
        self.session_id = uuid.uuid4().hex[:8]

        # Güvenli Kanal Topic'i (HiveMQ üzerinde benzersiz oda yolu)
        self.topic = f"aegisvault/v3/rooms/{self.room_name}"
        self.client: Optional[mqtt.Client] = None
        self.is_connected = False

    def connect(self):
        """Küresel kanala bağlanır ve şifreli dinlemeyi başlatır."""
        def worker():
            try:
                self.on_status("🟡 Küresel ağa bağlanılıyor (Türkiye ↔ Dünya)...")
                # MQTT v2 API ile istemci oluştur
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                self.client.on_connect = self._on_connect
                self.client.on_message = self._on_mqtt_message
                self.client.on_disconnect = self._on_disconnect

                self.client.connect(DEFAULT_BROKER, DEFAULT_PORT, keepalive=45)
                self.client.loop_start()
            except Exception as e:
                self.on_status(f"❌ Bağlantı hatası: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.is_connected = True
            client.subscribe(self.topic, qos=1)
            self.on_status(f"🟢 Odaya Bağlanıldı: '{self.room_name}' | AES-256-GCM Şifreleme Aktif!")
        else:
            self.on_status(f"❌ Sunucu bağlantıyı reddetti (Hata kodu: {rc})")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code=None, properties=None):
        self.is_connected = False
        self.on_status("🔴 Sohbet odası bağlantısı kesildi.")

    def _on_mqtt_message(self, client, userdata, msg):
        """Gelen şifreli paketi çözer."""
        try:
            token = msg.payload.decode("utf-8").strip()
            # AES-256-GCM ile çöz
            payload = crypto_chat.decrypt_message(token, self.room_key)
            full_text = payload.get("text", "")
            ts = payload.get("timestamp", datetime.now().strftime("%H:%M:%S"))

            # Format: SESSION_ID:USERNAME: MESSAGE
            parts = full_text.split(":", 2)
            if len(parts) == 3:
                msg_sid = parts[0]
                sender = parts[1]
                body = parts[2].lstrip()
            else:
                msg_sid = ""
                sender = "Bilinmeyen"
                body = full_text

            is_mine = (msg_sid == self.session_id)
            # Kendi gönderdiğimiz mesaj yerel olarak zaten eklendi, sadece karşı tarafı göster
            if not is_mine:
                self.on_message(sender, body, ts, False)
        except Exception:
            # Yanlış oda şifresi girilmişse veya kurcalanmışsa çözülemez
            pass

    def send_message(self, text: str) -> bool:
        """Mesajı AES-256-GCM ile zırhlayıp küresel kanala yayınlar."""
        if not self.client or not self.is_connected:
            return False

        try:
            # Oturum kimliği ve kullanıcı adıyla paketle
            formatted = f"{self.session_id}:{self.username}: {text}"
            token = crypto_chat.encrypt_message(formatted, self.room_key)
            self.client.publish(self.topic, token, qos=1)
            ts = datetime.now().strftime("%H:%M:%S")
            self.on_message(self.username, text, ts, True)
            return True
        except Exception as e:
            return False

    def close(self):
        self.is_connected = False
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.client = None
