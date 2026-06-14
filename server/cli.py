import threading
from server.session import ACTIVE_SESSIONS, session_lock
from simp_protocol import SimpHeader, MessageType, CommandPayload

def start_cli():
    print("\n[*] Wątek konsoli uruchomiony. Wpisz 'help' aby zobaczyć komendy.")
    cmd_seq_counter = 1
    
    while True:
        try:
            user_input = input("SIMP> ").strip()
            if not user_input:
                continue
            
            parts = user_input.split()
            cmd = parts[0].lower()

            if cmd == 'help':
                print("Dostępne komendy:")
                print("  list                       - Pokaż podłączone urządzenia")
                print("  interval <dev_id> <sekundy>- Zmień czas wysyłania (cmd_id=1)")
                print("  reboot <dev_id>            - Zrestartuj urządzenie (cmd_id=3)")
            
            elif cmd == 'list':
                with session_lock:
                    if not ACTIVE_SESSIONS:
                        print("Brak aktywnych sesji.")
                    else:
                        print(f"Aktywne sesje ({len(ACTIVE_SESSIONS)}):")
                        for dev_id in ACTIVE_SESSIONS:
                            print(f"  - Urządzenie ID: {dev_id}")
            
            elif cmd in ['interval', 'reboot']:
                if len(parts) < 2:
                    print(f"Błąd. Użycie: {cmd} <dev_id> [parametry]")
                    continue
                
                try:
                    target_id = int(parts[1])
                except ValueError:
                    print("Błąd: ID urządzenia musi być liczbą.")
                    continue
                
                with session_lock:
                    if target_id not in ACTIVE_SESSIONS:
                        print(f"[-] Urządzenie {target_id} nie jest podłączone.")
                        continue
                    conn = ACTIVE_SESSIONS[target_id]
                
                try:
                    if cmd == 'interval':
                        if len(parts) < 3:
                            print("Błąd: Podaj czas w sekundach.")
                            continue
                        param_bytes = parts[2].encode('utf-8')
                        payload = CommandPayload(cmd_id=1, cmd_seq=cmd_seq_counter, param=param_bytes)
                    
                    elif cmd == 'reboot':
                        payload = CommandPayload(cmd_id=3, cmd_seq=cmd_seq_counter, param=b"")

                    payload_bytes = payload.encode()
                    header = SimpHeader(
                        version=1,
                        msg_type=MessageType.COMMAND,
                        flags=0,
                        session_token=0,  
                        payload_len=len(payload_bytes)
                    )
                    
                    conn.sendall(header.encode() + payload_bytes)
                    print(f"[+] Wysłano komendę {cmd.upper()} do {target_id} (Sekwencja: {cmd_seq_counter})")
                    
                    cmd_seq_counter += 1
                except Exception as e:
                    print(f"[-] Błąd budowania/wysyłania komendy: {e}")
            else:
                print(f"Nieznana komenda: {cmd}")
                
        except EOFError:
            break
        except Exception as e:
            print(f"Błąd konsoli: {e}")