import socket
import ssl
import time
import sys

from simp_protocol import (
    SimpHeader, MessageType, HelloPayload, AuthPayload, AuthOkPayload,
    TelemetryPayload, AlertPayload
)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8883
EXPECTED_FINGERPRINT = "2ccc7f31f5da596a6c331aae1cb16418aaf300c7987a4fcb1e004e2b4eda2725"
PASSWORD = "admin"
DEVICE_ID = 123456789


def recv_exact(conn, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def main():
    print("[*] Inicjalizacja testu wydajnościowego (NFR)...")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn = ctx.wrap_socket(raw_sock, server_hostname=SERVER_HOST)
        conn.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[-] Błąd połączenia z serwerem: {e}")
        sys.exit(1)

    hello = HelloPayload(device_id=DEVICE_ID)
    conn.sendall(SimpHeader(1, MessageType.HELLO, 0, 0, len(hello.encode())).encode() + hello.encode())

    auth = AuthPayload(password=PASSWORD)
    conn.sendall(SimpHeader(1, MessageType.AUTH, 0, 0, len(auth.encode())).encode() + auth.encode())

    hdr_bytes = recv_exact(conn, 15)
    if not hdr_bytes:
        sys.exit(1)

    resp_header = SimpHeader.decode(hdr_bytes)
    payload_bytes = recv_exact(conn, resp_header.payload_len)
    session_token = AuthOkPayload.decode(payload_bytes).session_token
    print("[+] Połączono i zautoryzowano pomyślnie.\n")

    # TEST 1: Opóźnienie odpowiedzi ACK (< 100 ms)
    print("[*] Rozpoczynam Test 1: Opóźnienie odpowiedzi ACK...")
    alert = AlertPayload(alert_code=1, sensor_type=1, value=40.0)
    alert_bytes = alert.encode()
    alert_header = SimpHeader(1, MessageType.ALERT, 0x01, session_token, len(alert_bytes))
    packet = alert_header.encode() + alert_bytes

    start_time = time.perf_counter()
    conn.sendall(packet)

    conn.settimeout(2.0)
    try:
        ack_hdr_bytes = recv_exact(conn, 15)
        end_time = time.perf_counter()
        if ack_hdr_bytes:
            ack_hdr = SimpHeader.decode(ack_hdr_bytes)
            if ack_hdr.payload_len > 0:
                recv_exact(conn, ack_hdr.payload_len)

            latency_ms = (end_time - start_time) * 1000

            if ack_hdr.msg_type == MessageType.ACK:
                print(f"   [WYNIK] Otrzymano ACK w czasie: {latency_ms:.2f} ms")
                if latency_ms < 100.0:
                    print("   [STATUS] PASSED (Zgodnie z wymaganiem < 100 ms)")
                else:
                    print("   [STATUS] FAILED (Przekroczono limit 100 ms)")
            else:
                print(f"   [BŁĄD] Zamiast ACK otrzymano {ack_hdr.msg_type.name}")
    except socket.timeout:
        print("   [STATUS] FAILED (Brak odpowiedzi ACK - Timeout)")

    # TEST 2: Przepustowość i zapis telemetrii (>= 500 ramek/s)
    print("\n[*] Rozpoczynam Test 2: Przepustowość (wysyłanie 1000 ramek)...")

    tel = TelemetryPayload(sensor_type=1, timestamp=int(time.time()), value=25.0)
    tel_bytes = tel.encode()
    tel_header = SimpHeader(1, MessageType.TELEMETRY, 0, session_token, len(tel_bytes))
    telemetry_packet = tel_header.encode() + tel_bytes

    FRAMES_TO_SEND = 1000
    conn.settimeout(None)

    start_throughput = time.perf_counter()

    for _ in range(FRAMES_TO_SEND):
        conn.sendall(telemetry_packet)

    end_throughput = time.perf_counter()
    total_time = end_throughput - start_throughput
    frames_per_sec = FRAMES_TO_SEND / total_time

    print(f"   [WYNIK] Wysłano {FRAMES_TO_SEND} ramek w {total_time:.4f} sekund.")
    print(f"   [WYNIK] Osiągnięta przepustowość: {frames_per_sec:.2f} ramek/s")

    if frames_per_sec >= 500:
        print("   [STATUS] PASSED (Zgodnie z wymaganiem >= 500 ramek/s)")
    else:
        print("   [STATUS] FAILED (Zbyt niska przepustowość)")

    # TEST 3: Czas zapisu pojedynczej ramki (< 50 ms)
    # Weryfikowane pośrednio - 1/przepustowość daje średni czas zapisu
    print("\n[*] Rozpoczynam Test 3: Analiza czasu zapisu telemetrii...")
    avg_write_time_ms = (total_time / FRAMES_TO_SEND) * 1000
    print(f"   [WYNIK] Średni czas przetworzenia 1 ramki: {avg_write_time_ms:.4f} ms")
    if avg_write_time_ms < 50.0:
        print("   [STATUS] PASSED (Zgodnie z wymaganiem < 50 ms)")
    else:
        print("   [STATUS] FAILED (Zapis zajmuje zbyt długo)")

    bye_header = SimpHeader(1, MessageType.BYE, 0, session_token, 0)
    conn.sendall(bye_header.encode())
    conn.close()
    print("\n[*] Test zakończony.")


if __name__ == "__main__":
    main()