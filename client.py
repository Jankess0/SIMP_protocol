import socket
import ssl
import time
import random

# Importujemy struktury protokołu
from simp_protocol import (
    SimpHeader, MessageType, 
    HelloPayload, AuthPayload, AuthOkPayload, AuthFailPayload,
    TelemetryPayload
)

HOST = '127.0.0.1'
PORT = 8883

def recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
    """Czyta dokładnie n bajtów ze strumienia."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            raise ConnectionError("Połączenie przerwane przez serwer")
        data.extend(packet)
    return bytes(data)

def start_sensor():
    # 1. Konfiguracja TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations('server.crt')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] Łączenie z serwerem {HOST}:{PORT}...")
    
    try:
        sock.connect((HOST, PORT))
        tls_conn = context.wrap_socket(sock, server_hostname="localhost")
        print("[+] Zestawiono bezpieczne połączenie TLS 1.3")

        # ==========================================
        # KROK 1 & 2: HELLO + AUTH
        # ==========================================
        device_id = 123456789
        password = "admin"

        # Budowanie i wysyłanie HELLO
        hello_bytes = HelloPayload(device_id=device_id).encode()
        hello_header = SimpHeader(1, MessageType.HELLO, 0, 0, len(hello_bytes))
        tls_conn.sendall(hello_header.encode() + hello_bytes)
        print(f"[*] Wysłano HELLO (device_id: {device_id})")

        # Budowanie i wysyłanie AUTH
        auth_bytes = AuthPayload(password=password).encode()
        auth_header = SimpHeader(1, MessageType.AUTH, 0, 0, len(auth_bytes))
        tls_conn.sendall(auth_header.encode() + auth_bytes)
        print("[*] Wysłano AUTH (hasło)")

        # ==========================================
        # KROK 3: OCZEKIWANIE NA AUTH_OK
        # ==========================================
        resp_header_bytes = recv_exact(tls_conn, 15)
        resp_header = SimpHeader.decode(resp_header_bytes)
        resp_payload_bytes = recv_exact(tls_conn, resp_header.payload_len)

        if resp_header.msg_type == MessageType.AUTH_OK:
            session_token = AuthOkPayload.decode(resp_payload_bytes).session_token
            print(f"[SUKCES] Autoryzacja zakończona! Wydany token: {session_token}")
            
            # ==========================================
            # KROK 4: PĘTLA SYMULUJĄCA POMIARY (TELEMETRIA)
            # ==========================================
            print("\n[*] Rozpoczynam periodyczne wysyłanie telemetrii...")
            try:
                while True:
                    # Generujemy fałszywą temperaturę i pobieramy czas
                    temp_value = random.uniform(20.0, 25.0)
                    current_time = int(time.time())
                    
                    # 1 - przykładowy kod dla temperatury (SensorType.TEMP)
                    telemetry_payload = TelemetryPayload(
                        sensor_type=1, 
                        timestamp=current_time, 
                        value=temp_value
                    )
                    payload_bytes = telemetry_payload.encode()
                    
                    # UWAGA: Tutaj w nagłówku przekazujemy uzyskany session_token!
                    telemetry_header = SimpHeader(
                        version=1,
                        msg_type=MessageType.TELEMETRY,
                        flags=0,
                        session_token=session_token,
                        payload_len=len(payload_bytes)
                    )
                    
                    # Wysyłamy ramkę do serwera
                    tls_conn.sendall(telemetry_header.encode() + payload_bytes)
                    print(f"[->] Wysłano TELEMETRY: {temp_value:.2f}°C")
                    
                    # Czekamy 5 sekund przed kolejnym pomiarem
                    time.sleep(5)
                    
            except KeyboardInterrupt:
                print("\n[*] Zatrzymano symulację sensora.")
                # Dobre praktyki: przy zamykaniu wysyłamy ramkę BYE
                bye_header = SimpHeader(1, MessageType.BYE, 0, session_token, 0)
                tls_conn.sendall(bye_header.encode())
                
        elif resp_header.msg_type == MessageType.AUTH_FAIL:
            print("[BŁĄD] Serwer odrzucił autoryzację.")
        else:
            print(f"[!] Nieoczekiwany komunikat: {resp_header.msg_type.name}")

    except Exception as e:
        print(f"[-] Wystąpił błąd: {e}")
    finally:
        tls_conn.close()
        print("[-] Połączenie zamknięte.")

if __name__ == "__main__":
    start_sensor()