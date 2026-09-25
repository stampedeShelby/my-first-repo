"""Render the architecture / flow diagrams with Graphviz (`dot` must be installed).

    python docs/diagrams/make_diagrams.py
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

BASE = """
  graph [fontname="Helvetica", fontsize=13, bgcolor="white", pad=0.3, nodesep=0.35, ranksep=0.42, dpi=200];
  node  [fontname="Helvetica", fontsize=12, shape=box, style="rounded,filled", fillcolor="#ffffff",
         color="#51606f", penwidth=1.2, margin="0.18,0.07"];
  edge  [fontname="Helvetica", fontsize=10, color="#51606f", penwidth=1.2, arrowsize=0.7];
"""

VENDOR, DIST, CUST, ATT, OK, BAD, LOG = "#e8f1fb", "#f1f3f5", "#e8f6ee", "#fdecea", "#1a7f4b", "#b42318", "#fff6e0"

DIAGRAMS = {
"architecture": f"""digraph G {{ {BASE} rankdir=TB;
  subgraph cluster_v {{ label="VENDOR (trusted build & release zone)"; style="rounded,filled"; fillcolor="{VENDOR}"; color="#8fb3d9";
    dev [label="Developer\\n(commit, MFA)"]; repo [label="Source Repository\\n(protected branch)"];
    build [label="Secure CI/CD Build\\n(isolated builder)"]; tests [label="Security Testing\\n(exfiltration rules)"];
    hash [label="SHA-256\\nfingerprint + provenance"]; signer [label="Signing Service\\nHSM / KMS concept\\n(RBAC + MFA, Ed25519)", fillcolor="#d6e6f7"];
    man [label="Signed Manifest + Artifact\\n(+ detached signature)"];
    dev -> repo -> build -> tests -> hash -> signer -> man; }}
  subgraph cluster_d {{ label="DISTRIBUTION (untrusted)"; style="rounded,filled"; fillcolor="{DIST}"; color="#b8c0c8";
    reg [label="Artifact Registry\\n+ root-signed trust policy"]; tls [label="TLS 1.3 channel", shape=box, style="rounded,dashed,filled"]; }}
  subgraph cluster_c {{ label="CUSTOMER CI/CD (verification zone)"; style="rounded,filled"; fillcolor="{CUST}"; color="#94c9a9";
    cci [label="Customer CI/CD\\n(pinned root public key)"];
    eng [shape=record, style="rounded,filled", fillcolor="#ffffff", label="{{Verification Engine|{{Signature\\nverification|SHA-256\\nverification|Key\\nstatus}}|{{Artifact / version\\nstatus|Provenance|Security\\npolicy}}}}"];
    gate [label="Security Gate", shape=diamond, style="filled", fillcolor="#ffffff", margin="0.05,0.05"];
    dep [label="DEPLOY", fillcolor="#d5f0de", color="{OK}", fontcolor="{OK}"];
    blk [label="BLOCK\\n+ security event", fillcolor="#fbd9d6", color="{BAD}", fontcolor="{BAD}"];
    cci -> eng -> gate; gate -> dep [label=" all checks pass", fontcolor="{OK}"]; gate -> blk [label=" any failure", fontcolor="{BAD}"]; }}
  audit [label="Hash-chained Audit / Transparency Log", fillcolor="{LOG}", color="#b7791f"];
  man -> reg -> tls -> cci;
  dep -> audit; blk -> audit; signer -> audit [style=dashed, label=" every signing op"];
}}""",

"codecov_attack": f"""digraph G {{ {BASE} rankdir=LR; ranksep=0.35;
  a0 [label="Error in Docker image\\ncreation process", fillcolor="{ATT}", color="{BAD}"];
  a1 [label="Credential extracted\\n(HMAC key for GCS\\nservice account)", fillcolor="{ATT}", color="{BAD}"];
  a2 [label="Bash Uploader in\\ncloud storage modified\\n(from 31 Jan 2021)", fillcolor="{ATT}", color="{BAD}"];
  a3 [label="Customers download\\nvia HTTPS from the\\ngenuine domain"];
  a4 [label="Script runs in\\ncustomer CI", ];
  a5 [label="git remote -v + env\\n(tokens, keys) sent to\\nattacker server", fillcolor="{ATT}", color="{BAD}"];
  a6 [label="1 Apr 2021: customer\\nnotices checksum\\nmismatch", fillcolor="#e8f6ee", color="{OK}"];
  a0 -> a1 -> a2 -> a3 -> a4 -> a5; a3 -> a6 [style=dashed, label=" detected ~2 months later"];
}}""",

"key_management": f"""digraph G {{ {BASE} rankdir=LR;
  subgraph cluster_v {{ label="Vendor"; style="rounded,filled"; fillcolor="{VENDOR}"; color="#8fb3d9";
    vendor [label="Release manager\\n(RBAC role + TOTP MFA)"];
    svc [label="Secure Signing Service\\n(sign API only)"];
    hsm [label="HSM / KMS concept\\n(prototype: AES-256\\nencrypted PKCS#8, 0600)", fillcolor="#d6e6f7"];
    root [label="Root key (offline)\\nsigns trust policy only"];
    rel [label="Release key(s) Ed25519\\nactive / retired / revoked"];
    vendor -> svc -> hsm; hsm -> rel [dir=none, style=dashed]; hsm -> root [dir=none, style=dashed];
    root -> tp [label=" signs"]; rel -> svc [style=invis];
    tp [label="Trust policy vN\\nkeys + status + revoked\\nversions + min versions\\n(expires 30 days)", fillcolor="#ffffff"]; }}
  subgraph cluster_c {{ label="Customer"; style="rounded,filled"; fillcolor="{CUST}"; color="#94c9a9";
    pin [label="Pinned root\\npublic key (out-of-band)"];
    ver [label="Signature\\nverification"]; }}
  tp -> ver [label=" trusted release public keys"]; pin -> ver;
  log [label="Audit log: KEY_GENERATE, KEY_ROTATE,\\nKEY_REVOKE, SIGN_RELEASE ...", fillcolor="{LOG}", color="#b7791f"];
  svc -> log [style=dashed];
}}""",

"pipeline_gate": f"""digraph G {{ {BASE} rankdir=LR; ranksep=0.28; nodesep=0.25;
  node [fontsize=11];
  s1 [label="Build"]; s2 [label="Security\\ntests"]; s3 [label="SHA-256"]; s4 [label="Sign\\n(RBAC+MFA)"];
  s5 [label="Record\\nprovenance"]; s6 [label="Publish"]; s7 [label="TLS 1.3\\ndownload"];
  c1 [label="Verify\\nsignature"]; c2 [label="Verify\\nSHA-256"]; c3 [label="Key\\nstatus"]; c4 [label="Artifact /\\nversion status"];
  c5 [label="Provenance\\n+ policy"];
  d [label="DEPLOY", fillcolor="#d5f0de", color="{OK}", fontcolor="{OK}"];
  x [label="STOP PIPELINE\\nBLOCK + security event\\n+ audit record", fillcolor="#fbd9d6", color="{BAD}", fontcolor="{BAD}"];
  s1 -> s2 -> s3 -> s4 -> s5 -> s6 -> s7 -> c1 -> c2 -> c3 -> c4 -> c5 -> d;
  {{ s2 s4 c1 c2 c3 c4 c5 }} -> x [color="{BAD}", style=dashed, arrowsize=0.5];
  {{rank=same; c3; x}}
}}""",

"crypto_flow": f"""digraph G {{ {BASE} rankdir=LR;
  subgraph cluster_v {{ label="Vendor signing"; style="rounded,filled"; fillcolor="{VENDOR}"; color="#8fb3d9";
    art [label="Artifact bytes"]; h [label="SHA-256"]; prov [label="Provenance"];
    sa [label="Ed25519 sign\\n(ctx: artifact)"]; m [label="Manifest\\n{{artifact, version, sha256,\\nkey_id, timestamp,\\nartifact_signature,\\nprovenance_sha256}}"];
    sm [label="Ed25519 sign\\n(ctx: manifest)"]; sk [label="Private key\\n(never distributed)", shape=cylinder, fillcolor="#d6e6f7"];
    art -> h -> m; art -> sa -> m; prov -> m; m -> sm; sk -> sa [style=dashed]; sk -> sm [style=dashed]; }}
  subgraph cluster_c {{ label="Customer verification"; style="rounded,filled"; fillcolor="{CUST}"; color="#94c9a9";
    pk [label="Trusted public key\\n(from root-signed\\ntrust policy)", shape=cylinder];
    v1 [label="Verify manifest\\nsignature"]; v2 [label="Recompute SHA-256\\n= manifest.sha256 ?"]; v3 [label="Verify artifact\\nsignature"];
    ok [label="Integrity AND\\nauthenticity proven", fillcolor="#d5f0de", color="{OK}", fontcolor="{OK}"];
    pk -> v1; pk -> v3; v1 -> ok; v2 -> ok; v3 -> ok; }}
  sm -> v1 [label=" signed manifest"]; art -> v2 [label=" downloaded bytes"];
}}""",
}


def main() -> None:
    for name, src in DIAGRAMS.items():
        (HERE / f"{name}.dot").write_text(src)
        subprocess.run(["dot", "-Tpng", "-o", str(HERE / f"{name}.png"), str(HERE / f"{name}.dot")], check=True)
        subprocess.run(["dot", "-Tsvg", "-o", str(HERE / f"{name}.svg"), str(HERE / f"{name}.dot")], check=True)
        print("wrote", HERE / f"{name}.png")


if __name__ == "__main__":
    main()
