#!/usr/bin/env python3
"""Upload ./data to the board over HTTP (no cable needed)."""
import os, sys, requests
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.1"


def upload(path, rel):
    with open(path, "rb") as f:
        r = requests.post(f"http://{HOST}/upload",
                          files={"f": (rel, f)},
                          data={"path": rel}, timeout=20)
    print(f"{'OK ' if r.ok else 'ERR'} {rel}  ({os.path.getsize(path)} B)")


def main():
    jobs = []
    for base, _, files in os.walk(DATA):
        for name in files:
            full = os.path.join(base, name)
            rel = "/" + os.path.relpath(full, DATA).replace(os.sep, "/")
            jobs.append((full, rel))
    print(f"Uploading {len(jobs)} files to http://{HOST}")
    with ThreadPoolExecutor(4) as ex:
        for j in jobs:
            ex.submit(upload, *j)


if __name__ == "__main__":
    main()