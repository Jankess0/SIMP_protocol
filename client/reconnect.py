import time
import datetime
from collections import deque
from simp_protocol import SimpHeader, MessageType, TelemetryPayload


class ReconnectManager:
    def __init__(self):
        self.telemetry_buffer = deque(maxlen=100)
        self.backoff_steps = [5, 10, 20, 30]
        self.backoff_index = 0

    def flush_buffer(self, conn, session_token):
        """Opróżnia bufor i wysyła zaległe ramki po powrocie sieci."""
        if not self.telemetry_buffer:
            return

        print(f"[*] Wykryto {len(self.telemetry_buffer)} zaległych odczytów. Opróżniam bufor...")
        for past_telemetry in list(self.telemetry_buffer):
            t_bytes = past_telemetry.encode()
            t_header = SimpHeader(1, MessageType.TELEMETRY, 0, session_token, len(t_bytes))
            conn.sendall(t_header.encode() + t_bytes)

            past_time = datetime.datetime.fromtimestamp(past_telemetry.timestamp).strftime('%H:%M:%S')
            print(f" [^] Wysłano ZALEGŁE TELEMETRY z {past_time} -> {past_telemetry.value:.2f}°C")
            time.sleep(0.05)

        self.telemetry_buffer.clear()
        print("[+] Bufor opróżniony.")

    def handle_offline_mode(self):
        """Symuluje pomiary w trybie offline i zapisuje je do bufora."""
        wait_time = self.backoff_steps[self.backoff_index]
        print(f"[*] Tryb OFFLINE. Kolejna próba za {wait_time} sekund...")

        if self.backoff_index < len(self.backoff_steps) - 1:
            self.backoff_index += 1

        import random
        for _ in range(wait_time // 5):
            offline_val = random.uniform(20.0, 25.0)
            offline_ts = int(time.time())
            offline_payload = TelemetryPayload(sensor_type=1, timestamp=offline_ts, value=offline_val)
            self.telemetry_buffer.append(offline_payload)

            offline_time = datetime.datetime.fromtimestamp(offline_ts).strftime('%H:%M:%S')
            print(f" [Bufor] [{offline_time}] Zapisano odczyt w pamięci ({len(self.telemetry_buffer)}/100)")
            time.sleep(5)

    def reset_backoff(self):
        self.backoff_index = 0