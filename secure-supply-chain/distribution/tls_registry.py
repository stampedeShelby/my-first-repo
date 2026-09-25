"""Artifact registry served over HTTPS with TLS 1.3 only, plus a TLS 1.3 client.

TLS 1.3 (RFC 8446) protects the *channel*: confidentiality, server
authentication and integrity in transit, so a network man-in-the-middle cannot
swap the file on the wire. It does NOT prove the file on the server is the one
the vendor built – in the Codecov incident the malicious script was served
from the genuine domain over valid HTTPS. That is why the customer still runs
the signature verification in ``verifier/verify.py`` after every download.

For the prototype a local CA (ECDSA P-256) issues a certificate for
``localhost``/127.0.0.1; the client trusts only that CA and refuses any
protocol below TLS 1.3.

    python -m distribution.tls_registry serve --port 8443
    python -m distribution.tls_registry fetch secure-uploader-1.0.0.sh --port 8443
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import ssl
import threading
import http.client
import urllib.parse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common.workspace import Workspace


def _write_key(path: Path, key) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))


def ensure_tls_material(ws: Workspace) -> tuple[Path, Path, Path]:
    """Create (once) a local CA and a server certificate. Returns (ca_cert, server_cert, server_key)."""
    d = ws.tls_dir
    d.mkdir(parents=True, exist_ok=True)
    ca_cert_p, cert_p, key_p = d / "ca.crt", d / "server.crt", d / "server.key"
    if ca_cert_p.exists() and cert_p.exists() and key_p.exists():
        return ca_cert_p, cert_p, key_p

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SSCS Demo Registry CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                            content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    ca_cert_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_p, key)
    return ca_cert_p, cert_p, key_p


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):  # keep demo output clean
        pass


class RegistryServer:
    """Context manager running the HTTPS (TLS 1.3-only) registry in a background thread."""

    def __init__(self, ws: Workspace, host: str = "127.0.0.1", port: int = 0):
        self.ws = ws
        _, cert, key = ensure_tls_material(ws)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(cert, key)
        handler = partial(_QuietHandler, directory=str(ws.registry_dir))
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"https://localhost:{self.port}"

    def __enter__(self) -> "RegistryServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def client_context(ca_cert: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def fetch(ws: Workspace, base_url: str, filename: str, dest_dir: Path | None = None) -> dict:
    """Download one file over TLS 1.3 into the customer's download area."""
    ca_cert, _, _ = ensure_tls_material(ws)
    dest_dir = dest_dir or ws.downloads_dir
    dest_dir.mkdir(parents=True, exist_ok=True)
    host, port = urllib.parse.urlsplit(base_url).hostname, urllib.parse.urlsplit(base_url).port
    conn = http.client.HTTPSConnection(host, port, context=client_context(ca_cert), timeout=10)
    try:
        conn.connect()  # TLS handshake; record the negotiated parameters
        info = {"tls_version": conn.sock.version(), "cipher": conn.sock.cipher()[0]}
        conn.request("GET", "/" + urllib.parse.quote(filename))
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise FileNotFoundError(f"registry returned HTTP {resp.status} for {filename}")
    finally:
        conn.close()
    out = dest_dir / filename
    out.write_bytes(body)
    info["path"] = out
    return info


def main() -> None:
    ap = argparse.ArgumentParser(description="TLS 1.3 artifact registry")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8443)
    f = sub.add_parser("fetch"); f.add_argument("filename"); f.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()
    ws = Workspace.default().ensure()
    if args.cmd == "serve":
        srv = RegistryServer(ws, port=args.port)
        print(f"serving {ws.registry_dir} on {srv.base_url} (TLS 1.3 only) - Ctrl+C to stop")
        try:
            srv.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    else:
        info = fetch(ws, f"https://localhost:{args.port}", args.filename)
        print(f"downloaded {info['path']} via {info['tls_version']} ({info['cipher']})")


if __name__ == "__main__":
    main()
