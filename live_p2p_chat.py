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
import hmac
import hashlib
import threading
from collections import deque
from datetime import datetime
from typing import Callable, Optional
import paho.mqtt.client as mqtt
import crypto_chat
from crypto_utils import PQHybridKEM

DEFAULT_BROKER = "broker.hivemq.com"
DEFAULT_PORT = 1883
MAX_MQTT_PACKET_BYTES = 20 * 1024 * 1024  # 20 MB anti-DoS memory cap


class GlobalEncryptedChatSession:
    """Worldwide end-to-end encrypted messaging session with ZK blinded topics, anti-replay, and PQ-Hybrid KEM ratcheting."""

    def __init__(self, username: str, room_name: str, room_key: str, on_message: Callable, on_status: Callable):
        self.username = username.strip() or "Anonymous"
        self.room_name = room_name.strip().lower() or "general-room"
        self.base_room_key = room_key.strip()
        self.room_key = self.base_room_key
        self.pq_active = False
        self._ephemeral_pq_sk: Optional[str] = None
        self.on_message = on_message
        self.on_status = on_status
        self.session_id = uuid.uuid4().hex[:8]
        self._seen_nonces = deque(maxlen=512)

        # Zero-Knowledge Blinded Topic: Broker never sees plaintext room_name,
        # and outsiders without room_key cannot discover or flood the room topic.
        blind_id = hmac.new(
            self.base_room_key.encode("utf-8"),
            f"AEGIS-ZK-ROOM-v3:{self.room_name}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()[:28]
        self.topic = f"aegisvault/v3/zk/{blind_id}"
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
            self.on_status(f"🟢 Connected to Room: '{self.room_name}' | ZK-Topic & AES-256-GCM Active!")
        else:
            self.on_status(f"❌ Broker refused connection (RC: {rc})")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code=None, properties=None):
        self.is_connected = False
        self.on_status("🔴 Disconnected from chat room.")

    def initiate_pq_handshake(self) -> bool:
        """Initiates an ephemeral Post-Quantum Hybrid KEM (X25519 + Ring-LWE) key ratchet with room peers."""
        if not self.client or not self.is_connected:
            return False
        try:
            pub_k, priv_k = PQHybridKEM.generate_keypair()
            self._ephemeral_pq_sk = priv_k
            formatted = f"{self.session_id}:{self.username}: [PQ-KEM-SYN]:{pub_k}"
            token = crypto_chat.encrypt_message(formatted, self.base_room_key)
            self.client.publish(self.topic, token, qos=1)
            ts = datetime.now().strftime("%H:%M:%S")
            self.on_message("⚛️ PQ-KEM", "Broadcasting Ephemeral X25519 + Ring-LWE (q=3329) Public Key...", ts, True)
            return True
        except Exception:
            return False

    def _on_mqtt_message(self, client, userdata, msg):
        """Decrypts incoming cryptographic payload envelope and enforces anti-replay & PQ-KEM checks."""
        try:
            if not msg.payload or len(msg.payload) > MAX_MQTT_PACKET_BYTES:
                return  # Drop oversized DoS packets prior to allocation

            token = msg.payload.decode("utf-8").strip()
            # Try decrypting with current ratcheted key first, fallback to base_room_key for handshake packets
            payload = None
            for candidate_key in ([self.room_key, self.base_room_key] if self.room_key != self.base_room_key else [self.room_key]):
                try:
                    payload = crypto_chat.decrypt_message(token, candidate_key)
                    break
                except Exception:
                    continue
            if payload is None:
                return

            # Anti-replay verification (128-bit nonce deduplication + 10-minute freshness window)
            msg_nonce = payload.get("nonce")
            if msg_nonce:
                if msg_nonce in self._seen_nonces:
                    return  # Drop replayed packet
                self._seen_nonces.append(msg_nonce)

            msg_epoch = payload.get("epoch")
            if isinstance(msg_epoch, (int, float)) and abs(time.time() - msg_epoch) > 600:
                return  # Drop stale packet outside 10-minute replay window

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
            if is_mine:
                return

            # Check for Post-Quantum Hybrid KEM Handshake packets
            if body.startswith("[PQ-KEM-SYN]:"):
                peer_pk = body[len("[PQ-KEM-SYN]:"):].strip()
                ct_armored, shared_hex = PQHybridKEM.encapsulate(peer_pk)
                self.room_key = hashlib.sha3_256(f"{self.base_room_key}|PQ:{shared_hex}".encode("utf-8")).hexdigest()
                self.pq_active = True
                reply_fmt = f"{self.session_id}:{self.username}: [PQ-KEM-ACK]:{ct_armored}"
                reply_tok = crypto_chat.encrypt_message(reply_fmt, self.base_room_key)
                self.client.publish(self.topic, reply_tok, qos=1)
                self.on_status(f"⚛️ Connected: '{self.room_name}' | PQ-HYBRID (ML-KEM-LWE + X25519 + AES-256-GCM) ACTIVE!")
                self.on_message(
                    "⚛️ PQ-KEM",
                    f"Quantum-Resistant Handshake with '{sender}' completed! Session ratcheted (SHA3-256 ID: {shared_hex[:12]}...).",
                    ts,
                    False
                )
                return

            if body.startswith("[PQ-KEM-ACK]:") and self._ephemeral_pq_sk:
                ct_armored = body[len("[PQ-KEM-ACK]:"):].strip()
                shared_hex = PQHybridKEM.decapsulate(ct_armored, self._ephemeral_pq_sk)
                self._ephemeral_pq_sk = None  # Forward secrecy: destroy ephemeral private key immediately
                self.room_key = hashlib.sha3_256(f"{self.base_room_key}|PQ:{shared_hex}".encode("utf-8")).hexdigest()
                self.pq_active = True
                self.on_status(f"⚛️ Connected: '{self.room_name}' | PQ-HYBRID (ML-KEM-LWE + X25519 + AES-256-GCM) ACTIVE!")
                self.on_message(
                    "⚛️ PQ-KEM",
                    f"Quantum-Resistant Handshake confirmed by '{sender}'! Forward-secret session ratcheted (ID: {shared_hex[:12]}...).",
                    ts,
                    False
                )
                return

            self.on_message(sender, body, ts, False)
        except Exception:
            # Payloads with mismatched room keys or corrupted GHASH tags are discarded
            pass

    def send_message(self, text: str) -> bool:
        """Armors message with AES-256-GCM (and PQ-ratcheted key if active) and transmits to the global channel."""
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
        self._ephemeral_pq_sk = None
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.client = None

