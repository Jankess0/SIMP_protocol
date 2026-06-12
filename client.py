import socket
import ssl
import hashlib
import sys

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8883

EXPECTED_FINGERPRINT = "2ccc7f31f5da596a6c331aae1cb16418aaf300c7987a4fcb1e004e2b4eda2725"

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

def main():
    try:
        conn = create_tls_connection(SERVER_HOST, SERVER_PORT, EXPECTED_FINGERPRINT)

        print("[*] Zamykam połączenie (testowe).")
        conn.close()

    except Exception as e:
        print(f"\n[!] Błąd krytyczny klienta: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()