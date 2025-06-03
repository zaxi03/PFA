import time
import json
import MySQLdb
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re

LOG_PATH = "/mnt/modsec-logs/modsec_audit.log"

def get_connection():
    return MySQLdb.connect(
        host="db", user="root", password="root", database="flask_db"
    )

def insert_log(client_ip, host_cible, uri, method, attack_type, status, created_at):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO waf_logs (client_ip, host_cible, uri, method, attack_type, status, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (client_ip, host_cible, uri, method, attack_type, status, created_at)
    )
    conn.commit()
    conn.close()

def parse_and_insert(line):
    try:
        entry = json.loads(line.strip())
        tx = entry.get("transaction", {})
        client_ip = tx.get("client_ip")
        uri = tx.get("request", {}).get("uri", "/").split('?')[0]
        created_at = tx.get("time_stamp")
        date = datetime.strptime(created_at, "%a %b %d %H:%M:%S %Y")
        method=tx.get("request", {}).get("method", "UNKNOWN")
        host_cible=tx.get("request", {}).get("headers", {}).get("Host", "UNKNOWN")
        messages = tx.get("messages", [])
        if messages and "details" in messages[0]:
            tags = messages[0]["details"].get("tags", [])
            if len(tags) >= 4:
                attack_type = tags[3]
                attack_type = re.sub(r'^attack-', '', attack_type)
            else:
                attack_type = ""
        else:
            attack_type = ""

        status = "blocked" if tx.get("response", {}).get("http_code", 0) == 403 else "allowed"
        insert_log(client_ip, host_cible, uri, method, attack_type, status, date)
        print(client_ip, host_cible, uri, method, attack_type, status, date)

    except Exception as e:
        print(f"[ERREUR] Ligne ignorée : {e}")

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self._seek_end()

    def _seek_end(self):
        self._file = open(LOG_PATH, "r")
        self._file.seek(0, 2)  # fin du fichier

    def on_modified(self, event):
        if event.src_path.endswith("modsec_audit.log"):
            for line in self._file:
                parse_and_insert(line)

if __name__ == "__main__":
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/mnt/modsec-logs", recursive=False)
    observer.start()
    print("[INFO] Surveillance du fichier en cours...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
