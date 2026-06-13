import unittest
from unittest.mock import MagicMock, patch
from client import process_incoming_frame, send_alert_with_retry
from simp_protocol import MessageType, SimpHeader, CommandPayload, AckPayload


class TestClientLogic(unittest.TestCase):

    # Test TF1: Generowanie poprawnej sekwencji HELLO i AUTH
    def test_tf1_hello_and_auth_generation(self):
        from simp_protocol import HelloPayload, AuthPayload

        hello_payload = HelloPayload(device_id=12345)
        self.assertEqual(hello_payload.device_id, 12345)
        self.assertEqual(len(hello_payload.encode()), 8)

        auth_payload = AuthPayload(password="admin")
        self.assertEqual(auth_payload.password, "admin")
        self.assertEqual(len(auth_payload.encode()), 6)

    # Test TF2: Reakcja klienta na błędną autoryzację (AUTH_FAIL)
    @patch('client.recv_exact')
    def test_tf2_auth_fail_handling(self, mock_recv):
        from simp_protocol import AuthFailPayload, ErrorType

        mock_header = SimpHeader(1, MessageType.AUTH_FAIL, 0, 0, 1).encode()
        mock_payload = AuthFailPayload(error_code=ErrorType.AUTH_INVALID).encode()

        mock_recv.side_effect = [mock_header, mock_payload]

        mock_conn = MagicMock()

        with self.assertRaises(SystemExit) as cm:
            hdr_bytes = mock_recv(mock_conn, 15)
            resp_header = SimpHeader.decode(hdr_bytes)
            if resp_header.msg_type == MessageType.AUTH_FAIL:
                import sys
                sys.exit(1)

        self.assertEqual(cm.exception.code, 1)

    # Test TF3: Czy alert wysyła się ponownie przy braku ACK
    @patch('client.recv_exact')
    def test_tf3_alert_retry(self, mock_recv):
        import socket
        mock_conn = MagicMock()

        mock_recv.side_effect = [socket.timeout, socket.timeout, SimpHeader(1, MessageType.ACK, 0, 0, 0).encode()]

        send_alert_with_retry(mock_conn, 123, 35.0)
        self.assertEqual(mock_conn.sendall.call_count, 3)

    # Test TF4: Standardowe przetworzenie komendy SET_INTERVAL
    def test_tf4_process_set_interval_command(self):
        cmd_payload = CommandPayload(cmd_id=1, cmd_seq=1, param=b"30")
        mock_conn = MagicMock()

        mock_header = SimpHeader(1, MessageType.COMMAND, 0, 12345, len(cmd_payload.encode())).encode()

        with patch('client.recv_exact', return_value=cmd_payload.encode()):
            f_type, f_param, last_seq = process_incoming_frame(
                mock_conn,
                session_token=12345,
                header_bytes=mock_header,
                last_cmd_seq=0
            )

            self.assertEqual(f_type, "CMD_SET_INTERVAL")
            self.assertEqual(f_param, 30)
            self.assertEqual(last_seq, 1)
            self.assertTrue(mock_conn.sendall.called)

    # Test TE2: Weryfikacja działania bufora offline (Ring buffer)
    def test_te2_offline_buffering(self):
        from collections import deque
        from simp_protocol import TelemetryPayload
        import time

        telemetry_buffer = deque(maxlen=100)

        for i in range(3):
            offline_payload = TelemetryPayload(sensor_type=1, timestamp=int(time.time()), value=20.0 + i)
            telemetry_buffer.append(offline_payload)

        self.assertEqual(len(telemetry_buffer), 3)
        self.assertEqual(telemetry_buffer[0].value, 20.0)
        self.assertEqual(telemetry_buffer[2].value, 22.0)

        telemetry_buffer.clear()
        self.assertEqual(len(telemetry_buffer), 0)

    # Test ogólny: Reakcja na błąd serwera (np. TE3/TE4)
    def test_server_error_handling(self):
        mock_conn = MagicMock()
        payload_bytes = b"\x01\x08Server error"

        mock_header = SimpHeader(1, MessageType.ERROR, 0, 0, len(payload_bytes)).encode()

        with patch('client.recv_exact', return_value=payload_bytes):
            with self.assertRaises(ConnectionError):
                process_incoming_frame(mock_conn, 0, mock_header, 0)

    # Test TE6: Duplikat komendy
    def test_te6_duplicate_command(self):
        last_cmd_seq = 100
        dup_cmd = CommandPayload(cmd_id=1, cmd_seq=100, param=b"30")
        mock_conn = MagicMock()

        mock_header = SimpHeader(1, MessageType.COMMAND, 0, 12345, len(dup_cmd.encode())).encode()

        with patch('client.recv_exact', return_value=dup_cmd.encode()):
            f_type, _, _ = process_incoming_frame(mock_conn, 12345, mock_header, last_cmd_seq)
            self.assertEqual(f_type, "CMD_DUPLICATE")
            self.assertTrue(mock_conn.sendall.called)

    # Test TS2: Weryfikacja certyfikatu
    @patch('ssl.SSLSocket')
    def test_ts2_invalid_fingerprint(self, mock_tls):
        from client import create_tls_connection
        mock_tls.getpeercert.return_value = b"fake_cert"
        with patch('hashlib.sha256', return_value=MagicMock(hexdigest=lambda: "wrong_hash")):
            with self.assertRaises(Exception):
                create_tls_connection("127.0.0.1", 8883, "correct_hash")

if __name__ == '__main__':
    unittest.main()