"""
Global Encrypted Chat Network (Worldwide Relay & P2P Architecture)
Key Capabilities:
- Worldwide connectivity (e.g. UK to Turkey) without firewall port forwarding or IP exposure.
- Serverless client relay architecture via global MQTT broker (broker.hivemq.com).
- End-to-end military cryptography: messages are sealed with client-side AES-256-GCM before transmission.
- Intermediate brokers only observe encrypted ciphertext envelopes (AEGIS-MSG-v1:...).
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
    """Worldwide end-to-end encrypted messaging session."""

    def __init__(self, username: str, room_name: str, room_key: str, on_message: Callable, on_status: Callable):
        self.username = username.strip() or "Anonymous"
        self.room_name = room_name.strip().lower() or "general-room"
        self.room_key = room_key.strip()
        self.on_message = on_message
        self.on_status = on_status
        self.session_id = uuid.uuid4().hex[:8]

        # Unique topic path per tactical room
        self.topic = f"aegisvault/v3/rooms/{self.room_name}"
        self.client: Optional[mqtt.Client] = None
        self.is_connected = False

    def connect(self):
        """Connects to the global relay and begins encrypted message listening."""
        def worker():
            try:
                self.on_status(f"🟡 Connecting to global relay for room '{self.room_name}'...")
                # Instantiate client using MQTT v2 callback API
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
                self.client.on_connect = self._on_connect
                self.client.on_message = self._on_mqtt_message
                self.client.on_disconnect = self._on_disconnect

                self.client.connect(DEFAULT_BROKER, DEFAULT_PORT, keepalive=45)
                self.client.loop_start()
            except Exception as e:
                self.on_status(f"❌ Connection error: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.is_connected = True
            client.subscribe(self.topic, qos=1)
            self.on_status(f"🟢 Connected to Room: '{self.room_name}' | AES-256-GCM Tunnel Active!")
        else:
            self.on_status(f"❌ Broker refused connection (RC: {rc})")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code=None, properties=None):
        self.is_connected = False
        self.on_status("🔴 Disconnected from chat room.")

    def _on_mqtt_message(self, client, userdata, msg):
        """Decrypts incoming cryptographic payload envelope."""
        try:
            token = msg.payload.decode("utf-8").strip()
            # Decrypt AES-256-GCM authenticated payload
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
                sender = "Unknown"
                body = full_text

            is_mine = (msg_sid == self.session_id)
            # Only trigger callback for peers; local sender messages are appended immediately
            if not is_mine:
                self.on_message(sender, body, ts, False)
        except Exception:
            # Payloads with mismatched room keys or corrupted HMAC tags are discarded
            pass

    def send_message(self, text: str) -> bool:
        """Armors message with AES-256-GCM and transmits to the global channel."""
        if not self.client or not self.is_connected:
            return False

        try:
            formatted = f"{self.session_id}:{self.username}: {text}"
            token = crypto_chat.encrypt_message(formatted, self.room_key)
            self.client.publish(self.topic, token, qos=1)
            ts = datetime.now().strftime("%H:%M:%S")
            self.on_message(self.username, text, ts, True)
            return True
        except Exception:
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
