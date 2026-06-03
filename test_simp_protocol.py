import unittest
import struct
from simp_protocol import (
    SimpHeader, MessageType, ErrorType, 
    HelloPayload, AuthPayload, AuthOkPayload, AuthFailPayload,
    TelemetryPayload, AlertPayload, CommandPayload, AckPayload, 
    ErrorPayload, EmptyPayload
)

class TestSimpProtocol(unittest.TestCase):

    # ==========================================
    # TESTY NAGŁÓWKA
    # ==========================================
    def test_header_encode_decode(self):
        # Araange
        header = SimpHeader(
            version=1,
            msg_type=MessageType.TELEMETRY,
            flags=0x01,  
            session_token=0000000000000,
            payload_len=9
        )
        
        # Act
        encoded = header.encode()
        decoded = SimpHeader.decode(encoded)
        
        # Assert
        self.assertEqual(len(encoded), 15)
        self.assertEqual(header, decoded)

    def test_header_invalid_version(self):
        # Arrange
        bad_encoded = struct.pack(">BBBQI", 2, MessageType.PING.value, 0, 0, 0)
        
        # Act & Assert
        with self.assertRaisesRegex(ValueError, "Nieobsługiwana wersja"):
            SimpHeader.decode(bad_encoded)

    def test_header_payload_too_large(self):
        # Arrange
        bad_encoded = struct.pack(">BBBQI", 1, MessageType.TELEMETRY.value, 0, 0, 600)
        
        # Act & Assert
        with self.assertRaisesRegex(ValueError, "Przekroczenie limitu"):
            SimpHeader.decode(bad_encoded)

    # ==========================================
    # TESTY ŁADUNKÓW (PAYLOADS)
    # ==========================================
    def test_hello_payload(self):
        # Arrange
        payload = HelloPayload(device_id=987654321098765)
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(len(encoded), 8)
        self.assertEqual(payload, HelloPayload.decode(encoded))

    def test_auth_payload(self):
        # Arrange
        payload = AuthPayload(password="TajneHaslo123")
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(len(encoded), 14)
        self.assertEqual(payload, AuthPayload.decode(encoded))

    def test_auth_ok_payload(self):
        # Arrange
        payload = AuthOkPayload(session_token=999888777666)
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(len(encoded), 8)
        self.assertEqual(payload, AuthOkPayload.decode(encoded))

    def test_auth_fail_payload(self):
        # Arrange
        payload = AuthFailPayload(error_code=ErrorType.AUTH_INVALID)
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(len(encoded), 1)
        self.assertEqual(payload, AuthFailPayload.decode(encoded))

    def test_telemetry_payload(self):
        # Arrange
        payload = TelemetryPayload(
            sensor_type=1,
            timestamp=1700000000,
            value=23.5
        )
        
        # Act
        encoded = payload.encode()
        decoded = TelemetryPayload.decode(encoded)
        
        # Assert
        self.assertEqual(len(encoded), 9)
        self.assertEqual(payload.sensor_type, decoded.sensor_type)
        self.assertEqual(payload.timestamp, decoded.timestamp)
        self.assertAlmostEqual(payload.value, decoded.value, places=4)

    def test_alert_payload(self):
        # Arrange
        payload = AlertPayload(
            alert_code=255,
            sensor_type=2,
            value=99.9
        )
        
        # Act
        encoded = payload.encode()
        decoded = AlertPayload.decode(encoded)
        self.assertEqual(len(encoded), 6)
        
        # Assert
        self.assertEqual(payload.alert_code, decoded.alert_code)
        self.assertEqual(payload.sensor_type, decoded.sensor_type)
        self.assertAlmostEqual(payload.value, decoded.value, places=4)

    def test_command_payload(self):
        # Arrange
        payload = CommandPayload(
            cmd_id=5,
            cmd_seq=1024,
            param=b"interval=60s"
        )
        
        # Act
        encoded = payload.encode()
       
       # Assert
        self.assertEqual(len(encoded), 16)
        self.assertEqual(payload, CommandPayload.decode(encoded))

    def test_command_payload_too_long(self):
        # Arrange
        payload = CommandPayload(cmd_id=1, cmd_seq=1, param=b"x" * 33)
        
        # Act & Assert
        with self.assertRaisesRegex(ValueError, "Parametr komendy jest za długi"):
            payload.encode()

    def test_ack_payload(self):
        # Arrange
        payload = AckPayload(ack_seq=65535)
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(len(encoded), 2)
        self.assertEqual(payload, AckPayload.decode(encoded))

    def test_error_payload(self):
        # Arrange
        payload = ErrorPayload(
            error_code=ErrorType.FORMAT_ERROR,
            msg="Nieznany format ramki"
        )
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(payload, ErrorPayload.decode(encoded))

    def test_empty_payload(self):
        # Arrange
        payload = EmptyPayload()
        
        # Act
        encoded = payload.encode()
        
        # Assert
        self.assertEqual(encoded, b"")
        self.assertIsInstance(EmptyPayload.decode(encoded), EmptyPayload)

if __name__ == '__main__':
    unittest.main()