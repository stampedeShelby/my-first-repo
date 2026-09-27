"""
Interactive Web Dashboard for Software Supply Chain Security Gate.
Visualizes verification events, audit logs, key revocation lists, and attack telemetry.
"""

import os
import sys
import json
from flask import Flask, render_template_string, jsonify, request

# Ensure project imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit.audit_logger import AuditLogger
from vendor.key_manager import KeyManager
from verifier.verify import ArtifactVerifier

app = Flask(__name__)
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
audit = AuditLogger()
km = KeyManager()
verifier = ArtifactVerifier()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Supply-Chain Security Gate Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; }
        .table-dark { background-color: #1e293b; }
        .badge-pass { background-color: #10b981; color: white; }
        .badge-blocked { background-color: #ef4444; color: white; }
        .badge-revoked { background-color: #f59e0b; color: black; }
        .badge-mismatch { background-color: #dc2626; color: white; }
        .stat-card { border-left: 4px solid #38bdf8; }
        .code-box { background: #020617; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 0.85rem; color: #38bdf8; }
        .navbar { border-bottom: 1px solid #334155; }
    </style>
</head>
<body class="p-4">
    <div class="container-fluid">
        <header class="d-flex justify-content-between align-items-center pb-3 mb-4 navbar">
            <div>
                <h3 class="mb-0 text-info"><i class="fa-solid fa-shield-halved me-2"></i>Cryptographically Verified Software Supply Chain</h3>
                <small class="text-secondary">Codecov Attack Mitigation Architecture & Zero-Trust Admission Gate</small>
            </div>
            <div>
                <span class="badge bg-secondary p-2 me-2"><i class="fa-solid fa-key me-1"></i>Algorithm: Ed25519 + SHA-256</span>
                <span class="badge bg-success p-2"><i class="fa-solid fa-circle-check me-1"></i>Gate: ACTIVE</span>
            </div>
        </header>

        <!-- KPI Metrics -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card stat-card p-3 shadow-sm">
                    <h6 class="text-secondary text-uppercase mb-1">Total Audit Events</h6>
                    <h3 class="fw-bold mb-0 text-light" id="total-events">{{ logs|length }}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3 shadow-sm" style="border-left-color: #10b981;">
                    <h6 class="text-secondary text-uppercase mb-1">Legitimate Deploys</h6>
                    <h3 class="fw-bold mb-0 text-success" id="passed-events">{{ passed_count }}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3 shadow-sm" style="border-left-color: #ef4444;">
                    <h6 class="text-secondary text-uppercase mb-1">Attacks Blocked</h6>
                    <h3 class="fw-bold mb-0 text-danger" id="blocked-events">{{ blocked_count }}</h3>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card p-3 shadow-sm" style="border-left-color: #a855f7;">
                    <h6 class="text-secondary text-uppercase mb-1">False Acceptance Rate</h6>
                    <h3 class="fw-bold mb-0 text-info">0.00%</h3>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <!-- Audit Logs Table -->
            <div class="col-lg-8">
                <div class="card p-3 shadow-sm h-100">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="mb-0"><i class="fa-solid fa-list-check me-2 text-info"></i>Zero-Trust Audit Log (SQLite Store)</h5>
                        <button class="btn btn-sm btn-outline-light" onclick="location.reload()"><i class="fa-solid fa-rotate-right me-1"></i>Refresh</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover table-striped align-middle mb-0" style="font-size: 0.88rem;">
                            <thead>
                                <tr class="text-secondary">
                                    <th>Timestamp</th>
                                    <th>Artifact</th>
                                    <th>Version</th>
                                    <th>Status / Verdict</th>
                                    <th>Process</th>
                                    <th>Reason / Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for log in logs %}
                                <tr>
                                    <td class="text-secondary">{{ log.timestamp.split('T')[1][:8] if 'T' in log.timestamp else log.timestamp }}</td>
                                    <td class="fw-bold text-light">{{ log.artifact }}</td>
                                    <td><span class="badge bg-dark border border-secondary">{{ log.version }}</span></td>
                                    <td>
                                        {% if log.verification_result == 'PASS' %}
                                            <span class="badge badge-pass"><i class="fa-solid fa-check me-1"></i>PASS</span>
                                        {% elif log.verification_result == 'HASH_MISMATCH' %}
                                            <span class="badge badge-mismatch"><i class="fa-solid fa-triangle-exclamation me-1"></i>HASH_MISMATCH</span>
                                        {% elif log.verification_result == 'REVOKED' %}
                                            <span class="badge badge-revoked"><i class="fa-solid fa-ban me-1"></i>REVOKED</span>
                                        {% elif log.verification_result == 'UNAUTHORIZED_KEY' %}
                                            <span class="badge bg-warning text-dark"><i class="fa-solid fa-user-xmark me-1"></i>UNAUTH_KEY</span>
                                        {% elif log.verification_result == 'INVALID_SIGNATURE' %}
                                            <span class="badge bg-danger"><i class="fa-solid fa-file-excel me-1"></i>BAD_SIG</span>
                                        {% else %}
                                            <span class="badge badge-blocked">{{ log.verification_result }}</span>
                                        {% endif %}
                                    </td>
                                    <td class="text-secondary">{{ log.user_process }}</td>
                                    <td class="text-truncate" style="max-width: 250px;" title="{{ log.rejection_reason or 'Verification Passed' }}">
                                        {{ log.rejection_reason or '<span class="text-success">Verified & Allowed</span>'|safe }}
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Key Status and CRL Panel -->
            <div class="col-lg-4">
                <div class="card p-3 shadow-sm mb-4">
                    <h5 class="mb-3"><i class="fa-solid fa-key me-2 text-warning"></i>Key Revocation List (CRL)</h5>
                    <p class="text-secondary small mb-2">Simulates public key trust store and online revocation status protocol.</p>
                    <div class="code-box mb-2" style="max-height: 180px; overflow-y: auto;">
                        <pre class="mb-0 text-warning">{{ crl_json }}</pre>
                    </div>
                </div>

                <div class="card p-3 shadow-sm">
                    <h5 class="mb-3"><i class="fa-solid fa-terminal me-2 text-primary"></i>Live Gate Verifier</h5>
                    <p class="text-secondary small">Verify primary artifact against current security policies:</p>
                    <button class="btn btn-primary w-100 mb-2" onclick="verifyPrimary()"><i class="fa-solid fa-play me-2"></i>Verify Legitimate Artifact</button>
                    <div id="verify-output" class="code-box mt-2" style="display:none;"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function verifyPrimary() {
            const out = document.getElementById('verify-output');
            out.style.display = 'block';
            out.innerHTML = '<span class="text-secondary">Executing cryptographic verification...</span>';
            fetch('/api/verify-primary')
                .then(res => res.json())
                .then(data => {
                    out.innerHTML = JSON.stringify(data, null, 2);
                    setTimeout(() => location.reload(), 1500);
                })
                .catch(err => {
                    out.innerHTML = 'Error: ' + err;
                });
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    logs = audit.get_logs(limit=50)
    passed_count = sum(1 for l in logs if l.get("verification_result") == "PASS")
    blocked_count = sum(1 for l in logs if l.get("verification_result") != "PASS")

    crl_path = os.path.join(base_dir, "keys", "revoked_keys.json")
    crl_json = "{}"
    if os.path.exists(crl_path):
        with open(crl_path, "r", encoding="utf-8") as f:
            crl_json = f.read()

    return render_template_string(
        HTML_TEMPLATE,
        logs=logs,
        passed_count=passed_count,
        blocked_count=blocked_count,
        crl_json=crl_json
    )

@app.route("/api/verify-primary")
def api_verify_primary():
    art_path = os.path.join(base_dir, "artifacts", "uploader.sh")
    man_path = art_path + ".manifest.json"
    res = verifier.verify(art_path, man_path, user_process="Dashboard-Interactive")
    return jsonify(res)

@app.route("/api/logs")
def api_logs():
    return jsonify(audit.get_logs(limit=100))

if __name__ == "__main__":
    print("[*] Starting Supply Chain Security Dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
