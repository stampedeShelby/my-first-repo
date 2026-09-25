"""Generate a static HTML verification dashboard from the audit log.

    python -m dashboard.generate_dashboard      # writes dashboard/index.html

Shows: decision counters, hash-chain integrity, the latest security events and
the full audit trail (timestamp, actor, action, artifact, version, SHA-256,
key ID, result, rejection reason).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from audit.audit_logger import AuditLog
from common.workspace import PROJECT_ROOT, Workspace

GOOD = {"PASS", "OK", "DEPLOYED"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--muted:#5b6675;--line:#e3e7ec;--ok:#1a7f4b;--okbg:#e5f5ec;
--bad:#b42318;--badbg:#fdeceb;--warn:#8a5a00;--warnbg:#fff4de;--accent:#0b4f6c}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
header{background:var(--accent);color:#fff;padding:18px 28px}header h1{margin:0;font-size:20px}header p{margin:4px 0 0;opacity:.85}
main{padding:20px 28px;max-width:1300px;margin:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:28px}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:18px;overflow-x:auto}
h2{font-size:15px;margin:0 0 10px}table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
td:nth-child(-n+2){white-space:nowrap}code{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-weight:600;font-size:11.5px}
.ok{background:var(--okbg);color:var(--ok)}.bad{background:var(--badbg);color:var(--bad)}.info{background:#eef2f6;color:var(--muted)}
"""


def _tag(result: str) -> str:
    cls = "ok" if result in GOOD else "info" if result in ("INFO",) else "bad"
    return f'<span class="tag {cls}">{html.escape(result)}</span>'


def render(ws: Workspace) -> str:
    log = AuditLog.for_workspace(ws)
    events = log.events()
    ok, bad = log.verify_chain()
    verifies = [e for e in events if e["action"] == "VERIFY"]
    c = Counter(e["result"] for e in verifies)
    blocked = sum(v for k, v in c.items() if k != "PASS")
    sec_events = []
    if ws.security_events.exists():
        sec_events = [json.loads(l) for l in ws.security_events.read_text().splitlines() if l.strip()][-8:]

    kpis = [
        ("Verifications", len(verifies)), ("Deployed", c.get("PASS", 0)), ("Blocked", blocked),
        ("Signing ops", sum(1 for e in events if e["action"] == "SIGN_RELEASE" and e["result"] == "OK")),
        ("Audit chain", "INTACT" if ok else f"BROKEN @{bad}"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><span>{k}</span><b style="color:{"var(--bad)" if (k=="Blocked" and v) or str(v).startswith("BROKEN") else "var(--ink)"}">{v}</b></div>'
        for k, v in kpis)

    reasons = "".join(
        f"<tr><td>{html.escape(e['timestamp'])}</td><td>{_tag(e.get('status', e.get('decision','BLOCK')))}</td>"
        f"<td>{html.escape(str(e.get('artifact') or '-'))}@{html.escape(str(e.get('version') or '-'))}</td>"
        f"<td>{html.escape('; '.join(e.get('reasons', []))[:260])}</td></tr>" for e in reversed(sec_events))

    rows = "".join(
        f"<tr><td>{e['id']}</td><td>{html.escape(e['timestamp'])}</td><td>{html.escape(e['actor'])}</td>"
        f"<td>{html.escape(e['action'])}</td><td>{html.escape(str(e['artifact'] or '-'))}</td>"
        f"<td>{html.escape(str(e['version'] or '-'))}</td><td><code>{html.escape((e['sha256'] or '-')[:16])}</code></td>"
        f"<td><code>{html.escape(e['key_id'] or '-')}</code></td><td>{_tag(e['result'])}</td>"
        f"<td>{html.escape((e['reason'] or '')[:140])}</td></tr>" for e in reversed(events))

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Supply Chain Security Gate</title>
<style>{CSS}</style></head><body>
<header><h1>Cryptographically Verified Software Supply Chain - Security Gate Dashboard</h1>
<p>Every signing operation and every deploy/block decision, from the hash-chained audit log</p></header>
<main><div class="kpis">{kpi_html}</div>
<section><h2>Latest security events (blocked deployments)</h2><table>
<tr><th>Time (UTC)</th><th>Status</th><th>Artifact</th><th>Reasons</th></tr>{reasons or '<tr><td colspan=4>none</td></tr>'}</table></section>
<section><h2>Audit trail (newest first)</h2><table>
<tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Artifact</th><th>Version</th><th>SHA-256</th><th>Key ID</th><th>Result</th><th>Reason</th></tr>
{rows}</table></section></main></body></html>"""


def generate(ws: Workspace, out: Path | None = None) -> Path:
    out = out or PROJECT_ROOT / "dashboard" / "index.html"
    out.write_text(render(ws), encoding="utf-8")
    return out


if __name__ == "__main__":
    print(generate(Workspace.default()))
