import sys
import socket
from client.tls_client import recv_exact
from simp_protocol import (
    SimpHeader, MessageType, ErrorType,
    AlertPayload, ErrorPayload, CommandPayload, AckPayload
)


def send_alert_with_retry(conn, session_token, current_temp):
    """
    Wysyła ramkę ALERT i czeka na ACK.
    W przypadku braku odpowiedzi w ciągu 10s ponawia wysyłkę (max 3 razy).
    """
    print(f"\n[!] WYKRYTO ALARM: Temperatura {current_temp:.2f}°C przekracza próg!")
    alert_payload = AlertPayload(alert_code=1, sensor_type=1, value=current_temp)
    alert_bytes = alert_payload.encode()

    alert_header = SimpHeader(
        version=1, msg_type=MessageType.ALERT, flags=0x01,
        session_token=session_token, payload_len=len(alert_bytes)
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
    err_header = SimpHeader(1, MessageType.ERROR, 0, session_token, len(err_bytes))

    try:
        conn.sendall(err_header.encode() + err_bytes)
    except Exception:
        pass
    raise ConnectionError("Nie otrzymano ACK po 3 ponowieniach dla ALERT.")


def process_incoming_frame(conn, session_token, header_bytes, last_cmd_seq):
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

        if cmd_payload.cmd_seq == last_cmd_seq:
            print(f"[*] Wykryto duplikat komendy (seq: {cmd_payload.cmd_seq}). Zignorowano wykonanie.")
            return "CMD_DUPLICATE", None, last_cmd_seq

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
            return "CMD_SET_INTERVAL", new_interval, cmd_payload.cmd_seq
        elif cmd_id == 3:
            print("[!] Otrzymano komendę REBOOT. Wymuszam restart urządzenia...")
            return "CMD_REBOOT", None, cmd_payload.cmd_seq
        else:
            return "CMD_UNKNOWN", None, last_cmd_seq

    elif resp_header.msg_type == MessageType.ERROR:
        err_data = ErrorPayload.decode(payload_bytes)
        raise ConnectionError(f"Serwer odesłał ERROR! Kod: {err_data.error_code.name}, Msg: {err_data.msg}")
    elif resp_header.msg_type == MessageType.PONG:
        return "PONG", None, last_cmd_seq
    else:
        return resp_header.msg_type.name, None, last_cmd_seq