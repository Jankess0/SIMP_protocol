import sys
import time
import random
import socket
import select
import ssl
import datetime

from simp_protocol import (
    SimpHeader, MessageType, HelloPayload, AuthPayload, AuthOkPayload, TelemetryPayload
)
from client.tls_client import create_tls_connection, recv_exact
from client.sensor_sim import send_alert_with_retry, process_incoming_frame
from client.reconnect import ReconnectManager

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8883
DEVICE_ID = 123456789
PASSWORD = "admin"
EXPECTED_FINGERPRINT = "2ccc7f31f5da596a6c331aae1cb16418aaf300c7987a4fcb1e004e2b4eda2725"


def main():
    reconnect_mgr = ReconnectManager()
    print("[*] Uruchamiam symulator sensora SIMP...")

    while True:
        conn = None
        session_token = 0
        try:
            # 1. Nawiązanie połączenia (tls_client.py)
            conn = create_tls_connection(SERVER_HOST, SERVER_PORT, EXPECTED_FINGERPRINT)

            # 2. Rejestracja
            print(f"[*] Wysyłam HELLO (Device ID: {DEVICE_ID})...")
            hello_payload = HelloPayload(device_id=DEVICE_ID)
            conn.sendall(
                SimpHeader(1, MessageType.HELLO, 0, 0, len(hello_payload.encode())).encode() + hello_payload.encode())

            print("[*] Wysyłam AUTH (Hasło)...")
            auth_payload = AuthPayload(password=PASSWORD)
            conn.sendall(
                SimpHeader(1, MessageType.AUTH, 0, 0, len(auth_payload.encode())).encode() + auth_payload.encode())

            header_bytes = recv_exact(conn, 15)
            if not header_bytes:
                raise ConnectionError("Serwer zamknął połączenie przed autoryzacją.")

            resp_header = SimpHeader.decode(header_bytes)
            resp_payload_bytes = recv_exact(conn, resp_header.payload_len)

            if resp_header.msg_type == MessageType.AUTH_FAIL:
                print("[!] Autoryzacja odrzucona! Błędne hasło.")
                sys.exit(1)
            elif resp_header.msg_type == MessageType.AUTH_OK:
                session_token = AuthOkPayload.decode(resp_payload_bytes).session_token
                print(f"[+] Autoryzacja pomyślna! Token: {session_token}")
            else:
                raise ConnectionError("Nieoczekiwana ramka zamiast AUTH_OK.")

            # 3. Restarty sieci (reconnect.py)
            reconnect_mgr.reset_backoff()
            conn.settimeout(None)
            current_interval = 5
            reconnect_mgr.flush_buffer(conn, session_token)

            # 4. Główna pętla
            print("[*] Rozpoczynam wysyłanie telemetrii (CTRL+C aby przerwać)...")
            loops = 0
            last_cmd_seq = None

            while True:
                current_temp = random.uniform(20.0, 32.0)
                timestamp = int(time.time())

                if current_temp > 30.0:
                    send_alert_with_retry(conn, session_token, current_temp)
                else:
                    telemetry_payload = TelemetryPayload(sensor_type=1, timestamp=timestamp, value=current_temp)
                    telemetry_bytes = telemetry_payload.encode()
                    conn.sendall(SimpHeader(1, MessageType.TELEMETRY, 0, session_token,
                                            len(telemetry_bytes)).encode() + telemetry_bytes)

                    print(
                        f"[>] [{datetime.datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')}] Wysłano TELEMETRY: {current_temp:.2f}°C")

                if loops % 4 == 0:
                    conn.sendall(SimpHeader(1, MessageType.PING, 0, session_token, 0).encode())
                    pong_start = time.time()
                    pong_received = False
                    while time.time() - pong_start < 5.0:
                        ready, _, _ = select.select([conn], [], [], 5.0 - (time.time() - pong_start))
                        if ready:
                            hdr_bytes = recv_exact(conn, 15)
                            f_type, f_param, last_cmd_seq = process_incoming_frame(conn, session_token, hdr_bytes,
                                                                                   last_cmd_seq)
                            if f_type == "PONG":
                                pong_received = True
                                break
                            elif f_type == "CMD_SET_INTERVAL":
                                current_interval = f_param
                            elif f_type == "CMD_REBOOT":
                                sys.exit(0)
                        else:
                            break
                    if not pong_received:
                        raise ConnectionError("Brak odpowiedzi na PING (Timeout 5s).")

                sleep_start = time.time()
                while True:
                    elapsed = time.time() - sleep_start
                    time_left = current_interval - elapsed
                    if time_left <= 0: break
                    ready, _, _ = select.select([conn], [], [], time_left)
                    if ready:
                        hdr_bytes = recv_exact(conn, 15)
                        f_type, f_param, last_cmd_seq = process_incoming_frame(conn, session_token, hdr_bytes,
                                                                               last_cmd_seq)
                        if f_type == "CMD_SET_INTERVAL":
                            current_interval = f_param
                        elif f_type == "CMD_REBOOT":
                            sys.exit(0)
                    else:
                        break
                loops += 1

        except (socket.error, ConnectionError, ssl.SSLError) as e:
            print(f"\n[!] BŁĄD POŁĄCZENIA: {e}")
            if conn:
                try:
                    conn.close()
                except OSError:
                    pass

            reconnect_mgr.handle_offline_mode()

        except KeyboardInterrupt:
            print("\n[*] Zamykanie symulatora czujnika...")
            if conn:
                try:
                    conn.sendall(SimpHeader(1, MessageType.BYE, 0, session_token, 0).encode())
                except Exception:
                    pass
                conn.close()
            sys.exit(0)


if __name__ == "__main__":
    main()