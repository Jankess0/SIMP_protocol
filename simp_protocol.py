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