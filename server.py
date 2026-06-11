import socket
import ssl
import threading
import struct
import os

from simp_protocol import (
    SimpHeader, MessageType, ErrorType,
    HelloPayload, AuthPayload, AuthOkPayload, AuthFailPayload
)

HOST = '0.0.0.0'  
PORT = 8883       

# Słownik w formacie: { device_id: "hasło" }
AUTHORIZED_DEVICES = {
    123456789: "admin",
    987654321098765: "admin"
}

def recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
    """Pomocnicza funkcja - czyta z gniazda dokładnie n bajtów."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None  
        data.extend(packet)
    return bytes(data)

def handle_client(conn: ssl.SSLSocket, addr: tuple):
    """Funkcja obsługująca pojedynczego klienta w osobnym wątku."""
    print(f"\n[+] Nowe połączenie od: {addr}")
    try:

        # odbior HELLO
        header_bytes = recv_exact(conn, 15)
        if not header_bytes: return

        header = SimpHeader.decode(header_bytes)
        if header.msg_type != MessageType.HELLO:
            print(f"[-] Błąd protokołu: Oczekiwano HELLO, otrzymano {header.msg_type}")
            return
        
        payload_bytes = recv_exact(conn, header.payload_len)
        hello_payload = HelloPayload.decode(payload_bytes)
        device_id = hello_payload.device_id
        print(f"[*] Urządzenie (ID: {device_id}) zainicjowało sesję. Czekam na autoryzację...")

        # odbior AUTH
        header_bytes = recv_exact(conn, 15)
        if not header_bytes: return

        header = SimpHeader.decode(header_bytes)
        if header.msg_type != MessageType.AUTH:
            print("[-] Błąd protokołu: Oczekiwano AUTH po HELLO")
            return

        payload_bytes = recv_exact(conn, header.payload_len)
        auth_payload = AuthPayload.decode(payload_bytes)
        password = auth_payload.password

        # weryfikacja poswiadczen
        if device_id in AUTHORIZED_DEVICES and AUTHORIZED_DEVICES[device_id] == password:
            session_token = struct.unpack(">Q", os.urandom(8))[0]
            
            ok_payload = AuthOkPayload(session_token=session_token)
            ok_payload_bytes = ok_payload.encode()
            
            ok_header = SimpHeader(
                version=1, 
                msg_type=MessageType.AUTH_OK, 
                flags=0, 
                session_token=0, 
                payload_len=len(ok_payload_bytes)
            )
            
            conn.sendall(ok_header.encode() + ok_payload_bytes)
            print(f"[+] Autoryzacja udana! Wydano token sesji: {session_token}")
            
            # TODO: petla na TELEMETRY i PING
            
        else:
            # blad autoryzacji AUTH_FAIL
            fail_payload = AuthFailPayload(error_code=ErrorType.AUTH_INVALID)
            fail_payload_bytes = fail_payload.encode()
            
            fail_header = SimpHeader(
                version=1, 
                msg_type=MessageType.AUTH_FAIL, 
                flags=0, 
                session_token=0, 
                payload_len=len(fail_payload_bytes)
            )
            
            conn.sendall(fail_header.encode() + fail_payload_bytes)
            print(f"[-] Odrzucono próbę autoryzacji dla urządzenia: {device_id}")

    except Exception as e:
        print(f"[-] Błąd podczas obsługi sesji z {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Zamknięto połączenie z {addr}")

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server_socket.bind((HOST, PORT))
    server_socket.listen(50) 
    
    print(f"[*] Serwer SIMP nasłuchuje na {HOST}:{PORT}")

    try:
        while True:
            client_sock, addr = server_socket.accept()
            try:
                tls_conn = context.wrap_socket(client_sock, server_side=True)
                client_thread = threading.Thread(target=handle_client, args=(tls_conn, addr))
                client_thread.daemon = True 
                client_thread.start()
            except ssl.SSLError as e:
                print(f"[-] Błąd SSL z {addr}: {e}")
                client_sock.close()
    except KeyboardInterrupt:
        print("\n[*] Otrzymano sygnał zamknięcia. Wyłączanie serwera...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()