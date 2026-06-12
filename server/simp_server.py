import socket
import ssl
import threading

from server.session import handle_client
from server.storage import init_storage

HOST = '0.0.0.0'
PORT = 8883

def start_server():
    init_storage()

    # Konfiguracja TLS 1.3
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Konfiguracja gniazda TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    
    # 50 równoczesnych sensorów
    server_socket.listen(50) 
    
    print(f"[*] Serwer SIMP nasłuchuje na {HOST}:{PORT} z TLS 1.3...")

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
        print("\n[*] Wyłączanie serwera...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()