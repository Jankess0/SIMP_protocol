import os
import struct

AUTHORIZED_DEVICES = {
    123456789: "admin",
    987654321098765: "admin"
}

def verify_device(device_id: int, password: str) -> bool:
    """Weryfikuje, czy hasło dla danego ID sprzętowego jest poprawne."""
    return device_id in AUTHORIZED_DEVICES and AUTHORIZED_DEVICES[device_id] == password

def generate_session_token() -> int:
    """Generuje kryptograficznie bezpieczny, 8-bajtowy token sesji."""
    return struct.unpack(">Q", os.urandom(8))[0]