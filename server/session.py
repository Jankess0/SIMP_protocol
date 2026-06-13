import ssl
import threading
import socket

from simp_protocol import (
    SimpHeader, MessageType, ErrorType,
    HelloPayload, AuthPayload, AuthOkPayload, AuthFailPayload,
    TelemetryPayload, AlertPayload, AckPayload, ErrorPayload
)
from server.auth import verify_device, generate_session_token
from server.storage import save_telemetry

ACTIVE_SESSIONS = {}
session_lock = threading.Lock()

def add_session(device_id: int, conn: ssl.SSLSocket):
    """Bezpiecznie dodaje połączenie do rejestru."""
    with session_lock:
        ACTIVE_SESSIONS[device_id] = conn

def remove_session(device_id: int):
    """Bezpiecznie usuwa połączenie z rejestru."""
    with session_lock:
        if device_id in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[device_id]
            print(f"[*] Wyrejestrowano urządzenie {device_id} z aktywnych sesji.")

def recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
    """Czyta n bajtów ze strumienia."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def handle_client(conn: ssl.SSLSocket, addr: tuple):
    """Główna pętla stanów sesji dla wątku czujnika."""
    print(f"\n[+] Nowe bezpieczne połączenie od: {addr}")
    
    device_id = None
    
    try:
        conn.settimeout(15.0)
        
        # HELLO
        header_bytes = recv_exact(conn, 15)
        if not header_bytes: return
        header = SimpHeader.decode(header_bytes)
        if header.msg_type != MessageType.HELLO: return
        device_id = HelloPayload.decode(recv_exact(conn, header.payload_len)).device_id

        # AUTH 
        header_bytes = recv_exact(conn, 15)
        if not header_bytes: return
        header = SimpHeader.decode(header_bytes)
        if header.msg_type != MessageType.AUTH: return
        password = AuthPayload.decode(recv_exact(conn, header.payload_len)).password

        # WERYFIKACJA
        if verify_device(device_id, password):
            session_token = generate_session_token()
            ok_payload_bytes = AuthOkPayload(session_token=session_token).encode()
            ok_header = SimpHeader(1, MessageType.AUTH_OK, 0, 0, len(ok_payload_bytes))
            conn.sendall(ok_header.encode() + ok_payload_bytes)
            print(f"[+] Urządzenie {device_id} autoryzowane.")
            
            add_session(device_id, conn)
            conn.settimeout(35.0)

            # ACTIVE
            while True:
                next_header_bytes = recv_exact(conn, 15)
                if not next_header_bytes: break
                
                req_header = SimpHeader.decode(next_header_bytes)

                # Weryfikacja autoryzacji
                if req_header.session_token != session_token:
                    print(f"[-] Błąd tokenu dla urządzenia {device_id}")
                    err_payload = ErrorPayload(error_code=ErrorType.AUTH_INVALID, msg="Invalid token").encode()
                    err_header = SimpHeader(1, MessageType.ERROR, 0, session_token, len(err_payload)).encode()
                    conn.sendall(err_header + err_payload)
                    break

                req_payload_bytes = b""
                if req_header.payload_len > 0:
                    req_payload_bytes = recv_exact(conn, req_header.payload_len)

                # Przetwarzanie ramek TELEMETRY
                if req_header.msg_type == MessageType.TELEMETRY:
                    telemetry = TelemetryPayload.decode(req_payload_bytes)
                    save_telemetry(telemetry.timestamp, device_id, telemetry.sensor_type, telemetry.value)
                    print(f"[TELEMETRIA] {device_id} -> {telemetry.value:.2f}°C")
                
                # ALERT
                elif req_header.msg_type == MessageType.ALERT:  
                    alert = AlertPayload.decode(req_payload_bytes)
                    print(f"\n[!!!] ALERT KRYTYCZNY Z URZĄDZENIA {device_id} [!!!]")
                    print(f"      Typ czujnika: {alert.sensor_type}, Wartość: {alert.value:.2f}\n")
                    
                    # sprawdzenie czy flaga ACK_REQ i odesłanie ACK
                    if req_header.flags & 0x01:
                        ack_payload = AckPayload(ack_seq=1).encode()
                        ack_header = SimpHeader(1, MessageType.ACK, 0, session_token, len(ack_payload))
                        conn.sendall(ack_header.encode() + ack_payload)
                        print(f"[*] Odesłano potwierdzenie ACK do urządzenia {device_id}.")
                        
                # odebranie ACK po wysłaniu komendy
                elif req_header.msg_type == MessageType.ACK:
                    ack = AckPayload.decode(req_payload_bytes)
                    print(f"[+] Otrzymano ACK (seq: {ack.ack_seq}) od urządzenia {device_id}.")
                    
                elif req_header.msg_type == MessageType.PING:
                    pong_header = SimpHeader(1, MessageType.PONG, 0, session_token, 0)
                    conn.sendall(pong_header.encode())
                    
                elif req_header.msg_type == MessageType.BYE:
                    print(f"[*] Urządzenie {device_id} zakończyło sesję.")
                    break

        else:
            fail_payload_bytes = AuthFailPayload(error_code=ErrorType.AUTH_INVALID).encode()
            fail_header = SimpHeader(1, MessageType.AUTH_FAIL, 0, 0, len(fail_payload_bytes))
            conn.sendall(fail_header.encode() + fail_payload_bytes)
            print(f"[-] Odrzucono próbę autoryzacji dla: {device_id}")

    except socket.timeout:
        print(f"[-] TIMEOUT SESJI. Brak aktywności z {addr}. Rozłączanie.")
    except Exception as e:
        print(f"[-] Błąd w sesji z {addr}: {e}")
    finally:
        if device_id is not None:
            remove_session(device_id)
        conn.close()