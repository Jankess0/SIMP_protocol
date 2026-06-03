import struct
from enum import IntEnum
from dataclasses import dataclass

# typy wiadomosci
class MessageType(IntEnum):
    HELLO = 0x01
    AUTH = 0x02
    AUTH_OK = 0x03
    AUTH_FAIL = 0x04
    TELEMETRY = 0x05
    ALERT = 0x06
    COMMAND = 0x07
    ACK = 0x08
    PING = 0x09
    PONG = 0x0A
    ERROR = 0x0B
    BYE = 0x0C
    
class ErrorType(IntEnum):
    FORMAT_ERROR = 0x01
    AUTH_INVALID = 0x02
    VERSION_MISMATCH = 0x03
    TIMEOUT = 0x04
    STATE_ERROR = 0x05
    INTERNAL_ERROR = 0x06
    PAYLOAD_TOO_LARGE = 0x07
    RATE_LIMIT = 0x08
    
# nagłowek
HEADER_FORMAT = ">BBBQI" # 3x B char, Q long, I int (1+1+1+8+4=15 bajtow)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

@dataclass
class SimpHeader:
    version: int
    msg_type: MessageType
    flags: int
    session_token: int
    payload_len: int

    def encode(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            self.version,
            self.msg_type.value,
            self.flags,
            self.session_token,
            self.payload_len
        ) 
        
    @classmethod
    def decode(cls, data: bytes) -> 'SimpHeader':
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Ramka za krótka. Oczekiwano co najmniej {HEADER_SIZE} bajtów, otrzymano {len(data)}.")
        
        header_tuple = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        
        version = header_tuple[0]
        if version != 0x01:
            raise ValueError(f"Nieobsługiwana wersja protokołu: 0x{version:02X}")
        
        try:
            msg_type = MessageType(header_tuple[1])
        except ValueError:
            raise ValueError(f"Nieznany typ wiadomości: 0x{header_tuple[1]:02X}")
        
        payload_len = header_tuple[4]
        if payload_len > 512:
            raise ValueError(f"Przekroczenie limitu payloadu. Otrzymano {payload_len} (max 512).")

        return cls(
            version=header_tuple[0],
            msg_type=msg_type,
            flags=header_tuple[2],
            session_token=header_tuple[3],
            payload_len=header_tuple[4]
        )
        
@dataclass
class HelloPayload:
    device_id: int
    
    def encode(self) -> bytes:
        return struct.pack(">Q", self.device_id)
    
    @classmethod
    def decode(cls, data: bytes) -> 'HelloPayload':
        device_id = struct.unpack(">Q", data[:8])[0]
        return cls(device_id = device_id)
    
@dataclass
class AuthPayload:
    password: str
    
    def encode(self) -> bytes:
        pwd_bytes = self.password.encode('utf-8')
        pwd_len = len(pwd_bytes)
        format_string = f">B{pwd_len}s"
        return struct.pack(format_string, pwd_len, pwd_bytes)
    
    @classmethod
    def decode(cls, data: bytes) -> 'AuthPayload':
        pwd_len = data[0]
        password = data[1:1+pwd_len].decode('utf-8')
        return cls(password = password)

@dataclass
class AuthOkPayload:
    session_token: int
    
    def encode(self) -> bytes:
        return struct.pack(">Q", self.session_token)
    
    @classmethod
    def decode(cls, data: bytes) -> 'AuthOkPayload':
        session_token = struct.unpack(">Q", data[:8])[0]
        return cls(session_token=session_token)
    
@dataclass
class AuthFailPayload:
    error_code: ErrorType
    
    def encode(self) -> bytes:
        return struct.pack(">B", self.error_code.value)
    
    @classmethod
    def decode(cls, data: bytes) -> 'AuthFailPayload':
        error_code = struct.unpack(">B", data[:1])[0]
        return cls(error_code=ErrorType(error_code))


@dataclass
class TelemetryPayload:
    sensor_type: int
    timestamp: int
    value: float
    
    def encode(self) -> bytes:
        return struct.pack(">BIf", self.sensor_type, self.timestamp, self.value)
    
    @classmethod
    def decode(cls, data: bytes) -> 'TelemetryPayload':
        unpacked = struct.unpack(">BIf", data[:9])
        return cls(
            sensor_type=unpacked[0],
            timestamp=unpacked[1],
            value=unpacked[2]
        )
        
@dataclass
class AlertPayload:
    alert_code: int
    sensor_type: int
    value: float
    
    def encode(self) -> bytes:
        return struct.pack(">BBf", self.alert_code, self.sensor_type, self.value)
    
    @classmethod
    def decode(cls, data: bytes) -> 'AlertPayload':
        unpacked = struct.unpack(">BBf", data[:6])
        return cls(
            alert_code=unpacked[0],
            sensor_type=unpacked[1],
            value=unpacked[2]
        )
        
@dataclass
class CommandPayload:
    cmd_id: int
    cmd_seq: int
    param: bytes
    
    def encode(self) -> bytes:
        param_len = len(self.param)
        if param_len > 32:
            raise ValueError(f"Parametr komendy jest za długi ({param_len} B, max 32 B).")
        format_string = f">BHB{param_len}s"
        
        return struct.pack(format_string, self.cmd_id, self.cmd_seq, param_len, self.param)
        
    @classmethod
    def decode(cls, data: bytes) -> 'CommandPayload':
        cmd_id, cmd_seq, param_len = struct.unpack(">BHB", data[:4])
        
        param = data[4 : 4 + param_len]
        return cls(
            cmd_id=cmd_id,
            cmd_seq=cmd_seq,
            param=param
        )
        
@dataclass
class AckPayload:
    ack_seq: int
    
    def encode(self) -> bytes:
        return struct.pack(">H", self.ack_seq)
    
    @classmethod
    def decode(cls, data: bytes) -> 'AckPayload':
        ack_seq = struct.unpack(">H", data[:2])[0]
        return cls(ack_seq=ack_seq)
    
@dataclass
class ErrorPayload:
    error_code: ErrorType
    msg: str
    
    def encode(self) -> bytes:
        msg_bytes = self.msg.encode('utf-8')
        msg_len = len(msg_bytes)
        
        if msg_len > 64:
            raise ValueError(f"Wiadomość błędu za długa ({msg_len} B, max 64 B).")
            
        format_string = f">BB{msg_len}s"
        return struct.pack(format_string, self.error_code.value, msg_len, msg_bytes)
    
    @classmethod
    def decode(cls, data: bytes) -> 'ErrorPayload':
        error_code_val, msg_len = struct.unpack(">BB", data[:2])
        
        msg = data[2 : 2 + msg_len].decode('utf-8')
        return cls(
            error_code=ErrorType(error_code_val),
            msg=msg
        )
        
@dataclass
class EmptyPayload:
    def encode(self) -> bytes:
        return b""
    
    @classmethod
    def decode(cls, data: bytes) -> 'EmptyPayload':
        return cls()