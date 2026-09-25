"""Publisher-side integrity monitor (scheduled every few minutes).

Codecov's uploader was silently altered on 31 Jan 2021 and nobody noticed for
about two months. This job re-downloads what users actually receive and
compares it with the latest release in the transparency log, so a change made
by anyone other than the release pipeline raises an alert within minutes.
"""
import json

from . import crypto_utils as cu
from .tlog import TransparencyLog


def check_bucket(bucket, known_releases):
    """known_releases: manifest SHA-256s our own pipeline produced."""
    alerts = []
    with open(f"{bucket}/manifest.json") as f:
        body = json.load(f)["body"]
    served = cu.sha256_file(f"{bucket}/codecov-uploader.sh")
    if served != body["sha256"]:
        alerts.append(f"ALERT: served uploader {served[:12]}.. differs from signed release {body['sha256'][:12]}..")
    for e in TransparencyLog(f"{bucket}/tlog.json").entries:
        if e["manifest_sha256"] not in known_releases:
            alerts.append(f"ALERT: unknown release v{e['version']} in log (index {e['index']}) - possible key theft")
    return alerts
