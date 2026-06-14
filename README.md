# Protokół SIMP (Simple IoT Message Protocol)

Bezpieczny, dwukierunkowy protokół komunikacyjny IoT oparty o TLS 1.3 z interaktywną konsolą administracyjną (CLI) oraz trybem pracy offline (buforowaniem) po stronie klienta.

## 1. Wymagania Środowiskowe
* **Python 3.10 lub nowszy** (wyłącznie biblioteki standardowe, nie trzeba instalować paczek przez `pip`).
* Pliki certyfikatów `server.crt` oraz `server.key` pobrane z uczelnianego repozytorium GitHub muszą znajdować się w głównym katalogu projektu.

## 2. Instrukcja Uruchomienia
Wszystkie komendy należy wywoływać z **głównego poziomu projektu (`SIMP/`)**.

### Krok 1: Start Serwera
Uruchom serwer z flagą modułu `-m` (pozwala to na prawidłowe mapowanie paczki `server`):
python -m server.simp_server

### Krok 2: Start Klienta (Czujnika)
W nowym oknie terminala (pozostając w folderze `SIMP/`) wpisz:
python client.py

## 3. Komendy Konsoli Administracyjnej (Serwer CLI)
Polecenia można wpisywać bezpośrednio w terminalu uruchomionego serwera (znak zachęty `SIMP> `):

* `help` – Wyświetla listę poleceń.
* `list` – Wyświetla identyfikatory (ID) aktualnie połączonych urządzeń.
* `interval <device_id> <sekundy>` – Zdalnie zmienia częstotliwość wysyłania telemetrii przez czujnik (np. `interval 123456789 10`). 
* `reboot <device_id>` – Wymusza zdalny restart oprogramowania czujnika.

## 4. Główne Funkcje Odpornościowe
* **Odporność na duplikaty:** Serwer odrzuci próbę zalogowania drugiego urządzenia o tym samym ID (ochrona przed nadpisywaniem gniazd).
* **Timeouty sesji:** Serwer automatycznie rozłącza "martwe" wątki po 35 sekundach braku aktywności sieciowej.
* **Graceful Shutdown:** Wyłączenie serwera (`Ctrl+C`) wysyła w tle ramkę `BYE` do klientów, co natychmiast wprowadza je w bezbłędny tryb buforowania danych (offline).
