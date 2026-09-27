"""Figures for the final report/deck, describing the team's submitted implementation
(secure-supply-chain.zip): verifier/verify.py check order, vendor/sign.py manifest
signature, vendor/key_manager.py CRL lifecycle.

    python deliverables/tools/final/make_figures.py      (needs Graphviz `dot`)
"""

import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "final" / "figures"
REPO = HERE.parents[2]

BASE = """
  graph [fontname="Helvetica", fontsize=13, bgcolor="white", pad=0.3, nodesep=0.35, ranksep=0.42, dpi=200];
  node  [fontname="Helvetica", fontsize=12, shape=box, style="rounded,filled", fillcolor="#ffffff",
         color="#51606f", penwidth=1.2, margin="0.18,0.07"];
  edge  [fontname="Helvetica", fontsize=10, color="#51606f", penwidth=1.2, arrowsize=0.7];
"""
VENDOR, DIST, CUST, OK, BAD, LOG = "#e8f1fb", "#f1f3f5", "#e8f6ee", "#1a7f4b", "#b42318", "#fff6e0"

FIGS = {
"architecture": f"""digraph G {{ {BASE} rankdir=TB; newrank=true;
  subgraph cluster_v {{ label="VENDOR SECURE ZONE"; style="rounded,filled"; fillcolor="{VENDOR}"; color="#8fb3d9";
    dev [label="Developer"]; repo [label="Source repository\\n(approved repo URL)"];
    build [label="vendor/build.py\\nSHA-256 digest + SLSA provenance"];
    sign [label="vendor/sign.py\\ncanonical JSON manifest + Ed25519", fillcolor="#d6e6f7"];
    kms [label="Private key\\n(HSM / KMS in production)", shape=cylinder, fillcolor="#d6e6f7"];
    km [label="vendor/key_manager.py\\nkeys, rotation, CRL"];
    out [label="Artifact + signed manifest\\n+ provenance.json"];
    dev -> repo -> build -> sign -> out; kms -> sign [style=dashed]; km -> kms [dir=none, style=dashed]; }}
  subgraph cluster_d {{ label="UNTRUSTED DISTRIBUTION"; style="rounded,filled"; fillcolor="{DIST}"; color="#b8c0c8";
    store [label="Storage bucket / CDN / mirror\\n(simulated by artifacts/)"]; tls [label="TLS 1.3 transport\\n(protects the channel only)", style="rounded,dashed,filled"]; }}
  subgraph cluster_c {{ label="CUSTOMER CI/CD (ZERO-TRUST GATE)"; style="rounded,filled"; fillcolor="{CUST}"; color="#94c9a9";
    gate [label="ci/security_gate.py"];
    eng [shape=record, style="rounded,filled", fillcolor="#ffffff",
         label="{{verifier/verify.py|{{1 Schema|2 CRL|3 Policy}}|{{4 Ed25519 signature|5 SHA-256|6 Provenance}}}}"];
    dep [label="DEPLOY  (exit 0)", fillcolor="#d5f0de", color="{OK}", fontcolor="{OK}"];
    blk [label="BLOCK  (exit 1)", fillcolor="#fbd9d6", color="{BAD}", fontcolor="{BAD}"];
    gate -> eng; eng -> dep [label=" all pass", fontcolor="{OK}"]; eng -> blk [label=" any failure", fontcolor="{BAD}"]; }}
  crl [label="keys/revoked_keys.json (CRL)\\n+ trusted public keys + policy", fillcolor="{LOG}", color="#b7791f"];
  audit [label="audit/supply_chain_audit.db (SQLite)  ->  dashboard/app.py (Flask)", fillcolor="{LOG}", color="#b7791f"];
  out -> store -> tls -> gate; km -> crl [style=dashed]; crl -> eng [style=dashed];
  dep -> audit; blk -> audit;
}}""",

"verification_pipeline": f"""digraph G {{ {BASE} rankdir=LR; nodesep=0.28; ranksep=0.32;
  node [fontsize=11];
  s0 [label="Artifact +\\nmanifest\\npresent?"]; s1 [label="1. Manifest\\nschema"]; s2 [label="2. CRL\\nkey status"];
  s3 [label="3. Security\\npolicy"]; s4 [label="4. Ed25519\\nsignature"]; s5 [label="5. SHA-256\\nrecompute"];
  s6 [label="6. Provenance\\ndigest"]; ok [label="PASS\\nDEPLOY (exit 0)", fillcolor="#d5f0de", color="{OK}", fontcolor="{OK}"];
  s0 -> s1 -> s2 -> s3 -> s4 -> s5 -> s6 -> ok;
  node [fillcolor="#fbd9d6", color="{BAD}", fontcolor="{BAD}", fontsize=9.5];
  e0 [label="FILE_NOT_FOUND /\\nMANIFEST_NOT_FOUND"]; e1 [label="INVALID_\\nMANIFEST"]; e2 [label="REVOKED"];
  e3 [label="UNAUTHORIZED_KEY\\n(signer / key)\\nBLOCKED (version,\\nprovenance)"]; e4 [label="INVALID_\\nSIGNATURE\\n(or UNAUTHORIZED_KEY\\nif no public key)"];
  e5 [label="HASH_\\nMISMATCH"]; e6 [label="PROVENANCE_\\nMISMATCH"];
  edge [color="{BAD}", style=dashed, arrowsize=0.5];
  s0 -> e0; s1 -> e1; s2 -> e2; s3 -> e3; s4 -> e4; s5 -> e5; s6 -> e6;
  {{rank=same; s0; e0}} {{rank=same; s1; e1}} {{rank=same; s2; e2}} {{rank=same; s3; e3}}
  {{rank=same; s4; e4}} {{rank=same; s5; e5}} {{rank=same; s6; e6}}
}}""",

"crypto_flow": f"""digraph G {{ {BASE} rankdir=LR;
  subgraph cluster_v {{ label="Vendor: vendor/sign.py"; style="rounded,filled"; fillcolor="{VENDOR}"; color="#8fb3d9";
    art [label="Artifact bytes\\n(uploader.sh)"]; h [label="SHA-256"];
    m [label="Manifest\\n{{artifact, version, sha256,\\nalgorithm, signature_algorithm,\\nsigner, key_id, timestamp,\\nprovenance_ref}}"];
    c [label="Canonical JSON\\n(sorted keys, compact,\\nsignature excluded)"]; sg [label="Ed25519 sign"];
    sk [label="Private key\\n(never distributed)", shape=cylinder, fillcolor="#d6e6f7"];
    sm [label="manifest.json\\n+ \\"signature\\" (Base64)"];
    art -> h -> m -> c -> sg -> sm; sk -> sg [style=dashed]; }}
  subgraph cluster_c {{ label="Customer: verifier/verify.py"; style="rounded,filled"; fillcolor="{CUST}"; color="#94c9a9";
    pk [label="Trusted public key\\nkeys/<key_id>_pub.pem", shape=cylinder];
    v1 [label="Ed25519 verify over\\ncanonical manifest"]; v2 [label="Recompute SHA-256\\n== manifest.sha256 ?"];
    ok [label="Authentic AND\\nunmodified -> DEPLOY", fillcolor="#d5f0de", color="{OK}", fontcolor="{OK}"];
    pk -> v1; v1 -> ok; v2 -> ok; }}
  sm -> v1 [label=" signed manifest"]; art -> v2 [label=" downloaded bytes"];
}}""",

"key_lifecycle": f"""digraph G {{ {BASE} rankdir=TB; newrank=true; nodesep=0.45; ranksep=0.55;
  gen [label="1. Generate\\nEd25519 key pair\\n(OS CSPRNG)"];
  store [label="2. Store\\nPKCS#8 PEM (private)\\nSPKI PEM (public)\\noptional passphrase", fillcolor="#d6e6f7"];
  id [label="3. Identify\\nkey_id + SHA-256\\nfingerprint"];
  trust [label="4. Trust\\npublic key in keystore,\\nkey_id in policy\\nallowed_key_ids"];
  use [label="5. Sign releases\\n(sign.py refuses\\nrevoked keys)"];
  rot [label="6. Rotate\\nnew key generated,\\nold key -> CRL"];
  rev [label="7. Revoke\\nkeys/revoked_keys.json\\n(key_id, reason, time)", fillcolor="#fbd9d6", color="{BAD}"];
  ver [label="Verifier rejects every\\nmanifest signed by a\\nrevoked key: REVOKED", fillcolor="#fbd9d6", color="{BAD}", fontcolor="{BAD}"];
  hsm [label="Production: key generated and\\nkept inside HSM / cloud KMS", shape=note, fillcolor="{LOG}", color="#b7791f"];
  {{rank=same; hsm; gen; store; id; trust}}
  {{rank=same; ver; rev; rot; use}}
  hsm -> gen [style=dashed, arrowhead=none]; gen -> store -> id -> trust; trust -> use;
  rot -> use [dir=back]; rev -> rot [dir=back]; ver -> rev [dir=back];
  use -> rev [label=" compromise", constraint=false];
}}""",
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, src in FIGS.items():
        dot = OUT / f"{name}.dot"
        dot.write_text(src)
        subprocess.run(["dot", "-Tpng", "-o", str(OUT / f"{name}.png"), str(dot)], check=True)
        dot.unlink()
    # the documented incident flow is unchanged from the case-study analysis
    shutil.copy(REPO / "secure-supply-chain" / "docs" / "diagrams" / "codecov_attack.png", OUT / "codecov_attack.png")
    print("figures in", OUT)


if __name__ == "__main__":
    main()
