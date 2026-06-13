import threading
import time
import socket
import ssl
import random
import sys

from simp_protocol import (
    SimpHeader, MessageType, HelloPayload, AuthPayload, AuthOkPayload, TelemetryPayload
)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8883
EXPECTED_FINGERPRINT = "2ccc7f31f5da596a6c331aae1cb16418aaf300c7987a4fcb1e004e2b4eda2725"
PASSWORD = "admin"

connected_clients = 0
messages_sent = 0


def recv_exact(conn, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def simulated_sensor(device_id):
    global connected_clients, messages_sent
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = ctx.wrap_socket(raw_sock, server_hostname=SERVER_HOST)
        conn.connect((SERVER_HOST, SERVER_PORT))

        hello = HelloPayload(device_id=device_id)
        conn.sendall(SimpHeader(1, MessageType.HELLO, 0, 0, len(hello.encode())).encode() + hello.encode())

        auth = AuthPayload(password=PASSWORD)
        conn.sendall(SimpHeader(1, MessageType.AUTH, 0, 0, len(auth.encode())).encode() + auth.encode())

        hdr_bytes = recv_exact(conn, 15)
        if not hdr_bytes: return
        resp_header = SimpHeader.decode(hdr_bytes)

        if resp_header.msg_type != MessageType.AUTH_OK:
            return

        payload_bytes = recv_exact(conn, resp_header.payload_len)
        session_token = AuthOkPayload.decode(payload_bytes).session_token

        connected_clients += 1

        while True:
            time.sleep(random.uniform(3.0, 8.0))

            tel = TelemetryPayload(sensor_type=1, timestamp=int(time.time()), value=random.uniform(20.0, 32.0))
            tel_bytes = tel.encode()
            hdr = SimpHeader(1, MessageType.TELEMETRY, 0, session_token, len(tel_bytes))

            conn.sendall(hdr.encode() + tel_bytes)
            messages_sent += 1

    except Exception:
        pass


def main():
    print("[*] Uruchamianie Stress Testu dla 50 sensorów...")

    for i in range(50):
        t = threading.Thread(target=simulated_sensor, args=(123456789,), daemon=True)
        t.start()
        time.sleep(0.05)

    try:
        while True:
            print(f"[STATYSTYKI] Aktywne sensory: {connected_clients}/50 | Wysłane pakiety: {messages_sent}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Zamykanie stress testu.")
        sys.exit(0)


if __name__ == "__main__":
    main()