#!/usr/bin/env python3
import time
import json
import requests
import queue
import threading
import os

# Configuration
NEEV_API = "http://10.81.20.148:8000/api/v1/integrations"
TOKEN = "neev-wh-a7f3c9e2d1b4f8a6e3c7d9b2f5a8e1c4"
HEADERS = {
    "Content-Type": "application/json",
    "X-Webhook-Token": TOKEN
}

FILES_TO_WATCH = {
    "/var/log/suricata/eve.json": f"{NEEV_API}/suricata/eve",
    "/opt/zeek/logs/current/dns.log": f"{NEEV_API}/zeek/dns",
    "/opt/zeek/logs/current/http.log": f"{NEEV_API}/zeek/http",
    "/opt/zeek/logs/current/conn.log": f"{NEEV_API}/zeek/conn",
    "/opt/zeek/logs/current/ssl.log": f"{NEEV_API}/zeek/ssl",
    "/opt/zeek/logs/current/notice.log": f"{NEEV_API}/zeek/notice"
}

def tail_file(file_path, url):
    # Wait for file to exist
    while not os.path.exists(file_path):
        time.sleep(2)
        
    with open(file_path, "r") as f:
        # Seek to end
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            # Skip Zeek headers/comments
            if line.startswith("#"):
                continue
                
            try:
                # Try to parse as JSON or send raw depending on what API accepts,
                # but our script assumes JSON.
                payload = json.loads(line)
                requests.post(url, json=payload, headers=HEADERS, timeout=5)
            except Exception as e:
                pass # Silent fail to prevent log spam

def main():
    print("Starting Neev Log Shipper...")
    threads = []
    for file_path, url in FILES_TO_WATCH.items():
        t = threading.Thread(target=tail_file, args=(file_path, url), daemon=True)
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
