# Protokół SIMP (Simple IoT Message Protocol)

Bezpieczny, dwukierunkowy protokół komunikacyjny IoT oparty o TLS 1.3 z interaktywną konsolą administracyjną (CLI), trybem pracy offline (buforowaniem) oraz zautomatyzowanym środowiskiem testów wydajnościowych.

## 1. Wymagania Środowiskowe
* **Python 3.10 lub nowszy** (wyłącznie biblioteki standardowe).
* Pliki certyfikatów `server.crt` oraz `server.key` pobrane z repozytorium muszą znajdować się w głównym katalogu projektu.

## 2. Struktura Katalogów
Projekt został w pełni zmodularyzowany, oddzielając logikę backendu od frontendu czujnika:

📁 SIMP/
├── 📄 simp_protocol.py           # Wspólne struktury nagłówków i ładunków
├── 📄 simp_client.py             # Główny skrypt uruchomieniowy klienta
├── 📄 performance_test.py        # Zautomatyzowany test wymagań NFR (opóźnienia, przepustowość)
├── 📄 stress_test.py             # Test obciążeniowy (symulacja 50 czujników)
├── 📄 server.crt                 # Certyfikat publiczny serwera
├── 📄 server.key                 # Klucz prywatny serwera
├── 📁 server/                    # Moduły SERWERA
│   ├── 📄 simp_server.py         # Główny punkt wejścia (nasłuch TCP)
│   ├── 📄 session.py             # Zarządzanie sesjami, timeouty i obsługa ramek
│   ├── 📄 auth.py                # Weryfikacja poświadczeń i blokada duplikatów
│   ├── 📄 storage.py             # Moduł zapisu telemetrii do CSV
│   └── 📄 cli.py                 # Logika interaktywnej konsoli administratora
└── 📁 client/                    # Moduły KLIENTA
    ├── 📄 tls_client.py          # Nawiązywanie szyfrowanego połączenia TLS
    ├── 📄 sensor_sim.py          # Przetwarzanie ramek (komendy) i mechanika ponowień ALERT
    └── 📄 reconnect.py           # Zarządzanie buforem RAM i exponential backoff (offline)

## 3. Instrukcja Uruchomienia

Wszystkie komendy należy wywoływać z **głównego poziomu projektu (`SIMP/`)**.

### Standardowa praca (Serwer + Klient)
1. **Start Serwera:** Uruchom serwer jako moduł (pozwala to na mapowanie paczek):
   python -m server.simp_server
2. **Start Czujnika:** W osobnym terminalu uruchom symulator sprzętu:
   python -m client.simp_client

### Testy Wydajnościowe i Obciążeniowe
Projekt zawiera wbudowane narzędzia weryfikujące wymagania niefunkcjonalne (NFR). Uruchamiaj je tylko przy włączonym serwerze.

* **Test parametrów jakościowych (NFR):**
  Weryfikuje czas odpowiedzi ACK (<100ms) oraz przepustowość (>500 ramek/s).
  python performance_test.py

* **Test obciążeniowy (Stress Test):**
  Symuluje jednoczesne podłączenie 50 niezależnych wątków-czujników.
  python stress_test.py
  *Uwaga: Serwer posiada zabezpieczenie przed duplikatami ID. Aby 50 wątków z tym samym ID mogło się połączyć w trakcie testu, należy tymczasowo zakomentować sprawdzanie powielonych sesji w `server/session.py`.*

## 4. Komendy Konsoli Administracyjnej (Serwer CLI)
Polecenia można wpisywać bezpośrednio w terminalu pracującego serwera:
* `help` – Wyświetla listę poleceń.
* `list` – Wyświetla ID aktualnie połączonych urządzeń.
* `interval <device_id> <sekundy>` – Zdalnie zmienia częstotliwość wysyłania telemetrii przez czujnik (odsyła `ACK`). 
* `reboot <device_id>` – Wymusza zdalny restart oprogramowania czujnika.

## 5. Główne Funkcje Odpornościowe Systemu
* **Tryb Offline (Buforowanie):** W przypadku utraty łącza klient gromadzi dane w pamięci RAM (`deque`) i wysyła je zbiorczo po odzyskaniu połączenia z serwerem.
* **Certificate Pinning:** Klient sprzętowo odrzuca połączenia, jeśli skrót certyfikatu serwera nie pokrywa się z oczekiwanym (ochrona MITM).
* **Odporność na duplikaty:** Serwer odrzuca wtórne połączenia z tym samym ID, chroniąc spójność gniazd TCP.
* **Graceful Shutdown:** Kontrolowane wyłączenie serwera (`Ctrl+C`) wysyła w tle ramkę `BYE` do klientów, wymuszając natychmiastowe, bezbłędne przejście w tryb buforowania offline.