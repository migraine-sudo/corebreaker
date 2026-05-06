#!/usr/bin/env python3
"""
Test server for DNR CSP Bypass PoC.

Serves:
- /            → HTML page with strict CSP (only allows scripts from self)
- /allowed-script.js → A benign script (will be intercepted by extension)

The page's CSP is: script-src https://localhost:8443
This means ONLY scripts from https://localhost:8443 should execute.
data: URLs, inline scripts, and other origins are ALL blocked by CSP.

The extension's DNR rule redirects /allowed-script.js to a data: URL.
If CSP is properly enforced after redirect, the data: URL should be BLOCKED.
If the bug exists, the data: URL script EXECUTES (CSP bypass confirmed).

Usage:
  python3 server.py

Then navigate to https://localhost:8443/ in Safari with the PoC extension enabled.
"""

import http.server
import ssl
import os
import sys

PORT = 8443
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

class CSPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # Strict CSP: only allow scripts from self (localhost:8443)
            # data: URLs are NOT in the allowlist
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src https://localhost:8443; style-src 'unsafe-inline'; connect-src 'none'"
            )
            self.end_headers()
            self.wfile.write(PAGE_HTML.encode())

        elif self.path == "/allowed-script.js":
            # This script should be loaded normally (CSP allows it).
            # But the extension redirects it to a data: URL.
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'document.getElementById("status").textContent = "Script loaded normally (no bypass)";')

        elif self.path == "/no-extension-test":
            # Control page: same CSP, tries to load data: script directly
            # This SHOULD be blocked by CSP (baseline test)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src https://localhost:8443; style-src 'unsafe-inline'"
            )
            self.end_headers()
            self.wfile.write(CONTROL_HTML.encode())

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


PAGE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>DNR CSP Bypass PoC - Target Page</title>
    <style>
        body { font-family: monospace; padding: 2em; background: #1a1a2e; color: #eee; }
        .status { padding: 1em; margin: 1em 0; border-radius: 4px; }
        .safe { background: #0f3d0f; border: 1px solid #2d8f2d; }
        .vuln { background: #3d0f0f; border: 1px solid #8f2d2d; }
        .info { background: #0f2d3d; border: 1px solid #2d6f8f; }
        h1 { color: #00d4ff; }
        code { background: #333; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>DNR CSP Bypass PoC - Target Page</h1>

    <div class="status info">
        <strong>CSP Policy:</strong><br>
        <code>script-src https://localhost:8443</code><br><br>
        Only scripts from <code>https://localhost:8443</code> should execute.<br>
        <code>data:</code> URLs are NOT allowed by this CSP.
    </div>

    <div class="status safe" id="status-box">
        <strong>Status:</strong>
        <span id="status">Waiting for script to load...</span>
    </div>

    <div class="status info">
        <strong>What to expect:</strong><br>
        - Without extension: Status shows "Script loaded normally (no bypass)"<br>
        - With extension (if bug exists): Page content replaced with "CSP BYPASSED"<br>
        - With extension (if bug fixed): Script blocked, status stays "Waiting..."
    </div>

    <!-- This script tag loads from an allowed origin (self).
         The extension's DNR rule intercepts this request and redirects
         it to a data: URL containing attacker-controlled JavaScript.
         If CSP is re-validated after the redirect, the data: URL is blocked.
         If NOT re-validated (the bug), the attacker's script executes. -->
    <script src="https://localhost:8443/allowed-script.js"></script>

    <script nonce="should-not-work">
        // This inline script should be blocked by CSP (no 'unsafe-inline')
        // If it somehow runs, CSP is completely broken
        document.getElementById("status").textContent = "CRITICAL: inline script ran!";
    </script>
</body>
</html>
"""

CONTROL_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Control Test - Direct data: URL (should be blocked)</title>
    <style>
        body { font-family: monospace; padding: 2em; background: #1a1a2e; color: #eee; }
        .status { padding: 1em; margin: 1em 0; border-radius: 4px; }
        .safe { background: #0f3d0f; border: 1px solid #2d8f2d; }
        h1 { color: #00d4ff; }
        code { background: #333; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Control Test - Baseline CSP Enforcement</h1>

    <div class="status safe">
        <strong>Expected:</strong> The script below should be BLOCKED by CSP.<br>
        If you see this page unchanged, CSP is working correctly for direct data: URLs.
    </div>

    <div id="result">CSP is blocking data: scripts correctly (baseline confirmed)</div>

    <!-- This should be blocked by CSP since data: is not in script-src -->
    <script src="data:text/javascript;base64,ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Jlc3VsdCcpLnRleHRDb250ZW50ID0gJ0NTUCBGQUlMRUQ6IGRhdGE6IHNjcmlwdCBleGVjdXRlZCBkaXJlY3RseSc="></script>
</body>
</html>
"""


def generate_self_signed_cert():
    """Generate a self-signed cert for localhost testing."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"[+] Generated self-signed certificate: {CERT_FILE}, {KEY_FILE}")
        return True
    except ImportError:
        return False


def generate_cert_openssl():
    """Fallback: generate cert using openssl CLI."""
    ret = os.system(
        f'openssl req -x509 -newkey rsa:2048 -keyout {KEY_FILE} -out {CERT_FILE} '
        f'-days 365 -nodes -subj "/CN=localhost" 2>/dev/null'
    )
    return ret == 0


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[*] Generating self-signed TLS certificate for localhost...")
        if not generate_self_signed_cert():
            if not generate_cert_openssl():
                print("[-] Failed to generate certificate. Install 'cryptography' or 'openssl'.")
                sys.exit(1)

    server = http.server.HTTPServer(("localhost", PORT), CSPHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[+] Test server running at https://localhost:{PORT}/")
    print(f"[+] Target page:  https://localhost:{PORT}/")
    print(f"[+] Control test: https://localhost:{PORT}/no-extension-test")
    print(f"[+] CSP: script-src https://localhost:{PORT}")
    print(f"[*] Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
