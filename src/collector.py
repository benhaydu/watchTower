import time
import os
import requests
import re

LOG_FILE="test_auth.log"
batch =[]
lastLine = None
url="http://127.0.0.1:8000/ingest"
API_KEY = os.environ["WATCHTOWER_API_KEY"]


def stream_log(file_path):
    print(f"Watching {os.path.abspath(file_path)}")

    # Get starting position at the end of the file
    with open(file_path, "r") as f:
        f.seek(0, 2)
        position = f.tell()

    batch = []
    start_time = time.perf_counter()
    MAX_TIME = 10

    while True:
        with open(file_path, "r") as f:
            f.seek(position)
            new_lines = f.readlines()
            position = f.tell()

        for line in new_lines:
            print(f"Read line: {line.strip()}")
            batch.append(line.strip())
            if len(batch) >= 10:
                send_batch(batch)
                batch = []
                start_time = time.perf_counter()

        elapsed_time = time.perf_counter() - start_time
        if batch and elapsed_time > MAX_TIME:
            send_batch(batch)
            batch = []
            start_time = time.perf_counter()

        time.sleep(1)
        
def send_batch(batch):
    payload = {
        "source": "auth.log",
        "logs": batch
    }
    response = requests.post(url, json=payload, headers={"X-API-Key": API_KEY})
    print(f"Sent {len(batch)} lines, got status {response.status_code}")
    
if __name__ == "__main__":
    stream_log(LOG_FILE)