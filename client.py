import datetime
import socket
import ssl
import hashlib
import sys
import time
import random
import socket
import select
from collections import deque

from simp_protocol import (
    SimpHeader, MessageType, ErrorType,
    HelloPayload, AuthPayload, AuthOkPayload, AuthFailPayload,
    TelemetryPayload, AlertPayload, ErrorPayload,
    CommandPayload, AckPayload
)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8883

DEVICE_ID = 123456789
PASSWORD = "admin"

EXPECTED_FINGERPRINT = "2ccc7f31f5da596a6c331aae1cb16418aaf300c7987a4fcb1e004e2b4eda2725"

def recv_exact(conn, n: int) -> bytes:
    """Pomocnicza funkcja do bezpiecznego odbierania dokładnie n bajtów."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def create_tls_connection(host: str, port: int, expected_fingerprint: str) -> ssl.SSLSocket:
    """
    Nawiązuje połączenie TCP, inicjuje TLS 1.3 i weryfikuje certyfikat
    na podstawie odcisku palca (SHA-256).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    tls_sock = context.wrap_socket(raw_socket, server_hostname=host)

    try:
        print(f"[*] Próba połączenia z {host}:{port}...")
        tls_sock.connect((host, port))

        der_cert = tls_sock.getpeercert(binary_form=True)
        if not der_cert:
            raise ssl.SSLError("Serwer nie przedstawił certyfikatu!")

        cert_hash = hashlib.sha256(der_cert).hexdigest()

        if cert_hash.lower() != expected_fingerprint.lower():
            raise ssl.SSLError(
                f"Błąd weryfikacji certyfikatu!\n"
                f"Oczekiwano: {expected_fingerprint}\n"
                f"Otrzymano:  {cert_hash}"
            )

        print("[+] Połączenie TLS 1.3 nawiązane. Fingerprint certyfikatu zweryfikowany poprawnie.")
        return tls_sock

    except Exception as e:
        tls_sock.close()
        raise e


def send_alert_with_retry(conn, session_token, current_temp):
    """
    Wysyła ramkę ALERT i czeka na ACK.
    W przypadku braku odpowiedzi w ciągu 10s ponawia wysyłkę (max 3 razy).
    """
    print(f"\n[!] WYKRYTO ALARM: Temperatura {current_temp:.2f}°C przekracza próg!")

    alert_payload = AlertPayload(
        alert_code=1,
        sensor_type=1,
        value=current_temp
    )
    alert_bytes = alert_payload.encode()

    alert_header = SimpHeader(
        version=1,
        msg_type=MessageType.ALERT,
        flags=0x01,
        session_token=session_token,
        payload_len=len(alert_bytes)
    )
    packet = alert_header.encode() + alert_bytes

    max_retries = 3
    conn.settimeout(10.0)

    for attempt in range(1, max_retries + 2):
        if attempt > 1:
            print(f"[*] Brak ACK. Ponawiam wysyłkę ALERT (próba {attempt - 1}/{max_retries})...")

        conn.sendall(packet)

        try:
            header_bytes = recv_exact(conn, 15)
            if not header_bytes:
                print("[-] Serwer rozłączył się w trakcie oczekiwania na ACK.")
                sys.exit(1)

            resp_header = SimpHeader.decode(header_bytes)

            if resp_header.payload_len > 0:
                recv_exact(conn, resp_header.payload_len)

            if resp_header.msg_type == MessageType.ACK:
                print("[+] Otrzymano potwierdzenie ACK od serwera dla ALERTU.\n")

                conn.settimeout(1.0)
                return
            else:
                print(f"[-] Oczekiwano ACK, otrzymano {resp_header.msg_type.name}. Oczekuję dalej...")

        except socket.timeout:
            continue

    print("[-] Błąd krytyczny: Nie otrzymano ACK po 3 ponowieniach. Wysyłam ERROR TIMEOUT.")

    err_payload = ErrorPayload(error_code=ErrorType.TIMEOUT, msg="ACK timeout")
    err_bytes = err_payload.encode()

    err_header = SimpHeader(
        version=1,
        msg_type=MessageType.ERROR,
        flags=0,
        session_token=session_token,
        payload_len=len(err_bytes)
    )

    try:
        conn.sendall(err_header.encode() + err_bytes)
    except Exception:
        pass

    raise ConnectionError("Nie otrzymano ACK po 3 ponowieniach dla ALERT.")


def process_incoming_frame(conn, session_token, header_bytes):
    resp_header = SimpHeader.decode(header_bytes)
    payload_bytes = b""
    if resp_header.payload_len > 0:
        payload_bytes = recv_exact(conn, resp_header.payload_len)

    if resp_header.msg_type == MessageType.COMMAND:
        cmd_payload = CommandPayload.decode(payload_bytes)

        # Odsyłamy ACK
        ack_payload = AckPayload(ack_seq=cmd_payload.cmd_seq)
        ack_bytes = ack_payload.encode()
        ack_header = SimpHeader(1, MessageType.ACK, 0, session_token, len(ack_bytes))
        conn.sendall(ack_header.encode() + ack_bytes)
        print(f"[+] Otrzymano COMMAND (ID: {cmd_payload.cmd_id}). Wysłano ACK (seq: {cmd_payload.cmd_seq}).")

        cmd_id = cmd_payload.cmd_id
        if cmd_id == 1:
            try:
                if isinstance(cmd_payload.param, bytes):
                    new_interval = int(cmd_payload.param.decode().strip('\x00'))
                else:
                    new_interval = int(cmd_payload.param)
            except Exception:
                new_interval = 5
            print(f"[*] Wykonuję komendę SET_INTERVAL. Nowy interwał: {new_interval} s")
            return ("CMD_SET_INTERVAL", new_interval)

        elif cmd_id == 2:
            print("[*] Wykonuję komendę SET_THRESHOLD (Wkrótce wdrożone)...")
            return ("CMD_SET_THRESHOLD", cmd_payload.param)

        elif cmd_id == 3:
            print("[!] Otrzymano komendę REBOOT. Wymuszam restart urządzenia...")
            return ("CMD_REBOOT", None)

        else:
            print(f"[!] Nieznana komenda (ID: {cmd_id}). Ignoruję.")
            return ("CMD_UNKNOWN", None)

    elif resp_header.msg_type == MessageType.ERROR:
        err_data = ErrorPayload.decode(payload_bytes)
        raise ConnectionError(f"Serwer odesłał ERROR! Kod: {err_data.error_code.name}, Msg: {err_data.msg}")

    elif resp_header.msg_type == MessageType.PONG:
        return ("PONG", None)

    else:
        print(f"[!] Zignorowano nieoczekiwaną ramkę w tle: {resp_header.msg_type.name}")
        return (resp_header.msg_type.name, None)

def main():
    telemetry_buffer = deque(maxlen=100)
    backoff_steps = [5, 10, 20, 30]
    backoff_index = 0

    print("[*] Uruchamiam symulator sensora SIMP...")
    while True:
        conn = None
        try:
            #Nawiazanie polaczenia
            conn = create_tls_connection(SERVER_HOST, SERVER_PORT, EXPECTED_FINGERPRINT)

            #Init sesji - wyslanie HELLO
            print(f"[*] Wysyłam HELLO (Device ID: {DEVICE_ID})...")
            hello_payload = HelloPayload(device_id=DEVICE_ID)
            hello_bytes = hello_payload.encode()
            hello_header = SimpHeader(
                version=1,
                msg_type=MessageType.HELLO,
                flags=0,
                session_token=0,
                payload_len=len(hello_bytes)
            )
            conn.sendall(hello_header.encode() + hello_bytes)

            #Uwierzytelnienie - wyslanie AUTH
            print("[*] Wysyłam AUTH (Hasło)...")
            auth_payload = AuthPayload(password=PASSWORD)
            auth_bytes = auth_payload.encode()
            auth_header = SimpHeader(
                version=1,
                msg_type=MessageType.AUTH,
                flags=0,
                session_token=0,
                payload_len=len(auth_bytes)
            )
            conn.sendall(auth_header.encode() + auth_bytes)

            # Oczekiwanie na odpowiedz serwera
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
                print(f"[+] Autoryzacja pomyślna! Otrzymano token sesji: {session_token}")
            else:
                raise ConnectionError("Nieoczekiwana ramka zamiast AUTH_OK.")

            backoff_index = 0
            conn.settimeout(None)
            current_interval = 5

            if telemetry_buffer:
                print(f"[*] Wykryto {len(telemetry_buffer)} zaległych odczytów w pamięci offline. Opróżniam bufor...")
                for past_telemetry in list(telemetry_buffer):
                    t_bytes = past_telemetry.encode()
                    t_header = SimpHeader(1, MessageType.TELEMETRY, 0, session_token, len(t_bytes))
                    conn.sendall(t_header.encode() + t_bytes)
                    past_time = datetime.datetime.fromtimestamp(past_telemetry.timestamp).strftime('%H:%M:%S')
                    print(f" [^] Wysłano ZALEGŁE TELEMETRY z {past_time} -> {past_telemetry.value:.2f}°C")
                    time.sleep(0.05)

                telemetry_buffer.clear()
                print("[+] Bufor opróżniony.")

            #Cykliczne wyslanie telemetrii
            print("[*] Rozpoczynam wysyłanie telemetrii (CTRL+C aby przerwać)...")
            loops = 0

            while True:
                current_temp = random.uniform(20.0, 32.0)
                timestamp = int(time.time())

                if current_temp > 30.0:
                    send_alert_with_retry(conn, session_token, current_temp)
                else:
                    telemetry_payload = TelemetryPayload(sensor_type=1, timestamp=timestamp, value=current_temp)
                    telemetry_bytes = telemetry_payload.encode()
                    telemetry_header = SimpHeader(1, MessageType.TELEMETRY, 0, session_token, len(telemetry_bytes))

                    conn.sendall(telemetry_header.encode() + telemetry_bytes)
                    current_time = datetime.datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                    print(f"[>] [{current_time}] Wysłano TELEMETRY: {current_temp:.2f}°C")

                if loops % 4 == 0:
                    ping_header = SimpHeader(1, MessageType.PING, 0, session_token, 0)
                    conn.sendall(ping_header.encode())

                    pong_start = time.time()
                    pong_received = False
                    while time.time() - pong_start < 5.0:
                        ready, _, _ = select.select([conn], [], [], 5.0 - (time.time() - pong_start))
                        if ready:
                            hdr_bytes = recv_exact(conn, 15)
                            if not hdr_bytes:
                                raise ConnectionError("Brak odpowiedzi na PING (EOF).")

                            f_type, f_param = process_incoming_frame(conn, session_token, hdr_bytes)
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
                    if time_left <= 0:
                        break

                    ready, _, _ = select.select([conn], [], [], time_left)
                    if ready:
                        hdr_bytes = recv_exact(conn, 15)
                        if not hdr_bytes:
                            raise ConnectionError("Rozłączono (EOF) w trakcie nasłuchiwania.")

                        f_type, f_param = process_incoming_frame(conn, session_token, hdr_bytes)
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
                except:
                    pass

            wait_time = backoff_steps[backoff_index]
            print(f"[*] Tryb OFFLINE. Kolejna próba za {wait_time} sekund...")

            if backoff_index < len(backoff_steps) - 1:
                backoff_index += 1

            for _ in range(wait_time // 5):
                offline_val = random.uniform(20.0, 25.0)
                offline_ts = int(time.time())
                offline_payload = TelemetryPayload(sensor_type=1, timestamp=offline_ts, value=offline_val)
                telemetry_buffer.append(offline_payload)
                offline_time = datetime.datetime.fromtimestamp(offline_ts).strftime('%H:%M:%S')
                print(f" [Bufor] [{offline_time}] Zapisano odczyt w pamięci lokalnej ({len(telemetry_buffer)}/100)")
                time.sleep(5)

        except KeyboardInterrupt:
            print("\n[*] Zamykanie symulatora czujnika...")
            if conn:
                try:
                    bye_header = SimpHeader(1, MessageType.BYE, 0, session_token, 0)
                    conn.sendall(bye_header.encode())
                except:
                    pass
                conn.close()
            sys.exit(0)


if __name__ == "__main__":
    main()