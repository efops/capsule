"""A batch job: it does its work once, writes a report, and exits.

Each run appends to /data/report.txt, a volume, so the reports accumulate
across runs. A non-zero exit status would mark the run as failed.
"""
import datetime
import hashlib
from pathlib import Path

report = Path("/data/report.txt")
runs = len(report.read_text().splitlines()) + 1 if report.exists() else 1

# Stand-in for real work: hash a million numbers.
digest = hashlib.sha256()
for n in range(1_000_000):
    digest.update(str(n).encode())

line = f"run {runs} at {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%dT%H:%M:%SZ} result {digest.hexdigest()[:16]}"
with report.open("a") as f:
    f.write(line + "\n")
print(line)
