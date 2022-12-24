
import os
import time

IPLOG_LABEL = os.getenv('IPLOG_LABEL', 'taserver')
IPLOG_FILE = os.getenv('IPLOG_FILE', 'iplog.tsv')


def add(ip: str, user_id: int, display_name: str):
  try:
    with open(IPLOG_FILE, 'a') as f:
      f.write(f"{IPLOG_LABEL}\t{int(time.time() * 1000)}\t{user_id}\t{display_name}\t{ip}\n")
  except Exception as e:
    print(f"Failed to log IP ip:{ip}/user:{user_id} ({display_name}) {e}")