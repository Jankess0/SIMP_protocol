import csv
import os

CSV_FILE = "telemetry_data.csv"

def init_storage():
    """Inicjalizuje plik CSV z nagłówkami, jeśli nie istnieje."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "device_id", "sensor_type", "value"])

def save_telemetry(timestamp: int, device_id: int, sensor_type: int, value: float):
    """Dopisuje nowy rekord telemetrii do bazy (CSV)."""
    with open(CSV_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, device_id, sensor_type, round(value, 4)])