import socket
import ssl
import hashlib
import sys
import time
import random
import socket
from simp_protocol import (
    SimpHeader, MessageType, ErrorType,
    HelloPayload, AuthPayload, AuthOkPayload, AuthFailPayload,
    TelemetryPayload, AlertPayload
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

    print("[-] Błąd krytyczny: Nie otrzymano ACK po 3 ponowieniach.")

    conn.close()
    sys.exit(1)

def main():
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
            fail_payload = AuthFailPayload.decode(resp_payload_bytes)
            print(f"[!] Autoryzacja odrzucona! Kod błędu: {fail_payload.error_code.name}")
            conn.close()
            sys.exit(1)

        elif resp_header.msg_type == MessageType.AUTH_OK:
            ok_payload = AuthOkPayload.decode(resp_payload_bytes)
            session_token = ok_payload.session_token
            print(f"[+] Autoryzacja pomyślna! Otrzymano token sesji: {session_token}")
        else:
            print(f"[!] Nieoczekiwana odpowiedź serwera: {resp_header.msg_type.name}")
            conn.close()
            sys.exit(1)

        #Cykliczne wyslanie telemetrii
        print("[*] Rozpoczynam wysyłanie telemetrii (CTRL+C aby przerwać)...")
        conn.settimeout(1.0)

        while True:
            current_temp = random.uniform(20.0, 32.0)
            timestamp = int(time.time())

            if current_temp > 30.0:
                send_alert_with_retry(conn, session_token, current_temp)
                time.sleep(5)
                continue

            telemetry_payload = TelemetryPayload(
                sensor_type=1,
                timestamp=timestamp,
                value=current_temp
            )
            telemetry_bytes = telemetry_payload.encode()

            telemetry_header = SimpHeader(
                version=1,
                msg_type=MessageType.TELEMETRY,
                flags=0,
                session_token=session_token,  # zapisany token
                payload_len=len(telemetry_bytes)
            )

            conn.sendall(telemetry_header.encode() + telemetry_bytes)
            print(f"[>] Wysłano TELEMETRY: {current_temp:.2f}°C")

            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[*] Zamykanie symulatora czujnika...")
    except Exception as e:
        print(f"\n[!] Błąd krytyczny klienta: {e}")
        sys.exit(1)
    finally:
        if 'conn' in locals():
            conn.close()
            print("[*] Połączenie zamknięte.")


if __name__ == "__main__":
    main()