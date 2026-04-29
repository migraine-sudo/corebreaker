#!/usr/bin/env python3
"""HTTP server with Permission-Policy headers for PoC testing."""
import http.server
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888

class PPHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        if 'gamepad_pp_bypass_host' in self.path:
            self.send_header('Permissions-Policy', 'gamepad=()')
        super().end_headers()

httpd = http.server.HTTPServer(("127.0.0.1", port), PPHandler)
print(f"Serving on http://localhost:{port}/")
print(f"PoC pages:")
print(f"  Gamepad PP bypass: http://localhost:{port}/gamepad_pp_bypass_host.html")
print(f"  Digital Credentials: http://localhost:{port}/digital_credentials_poc.html")
print("Press Ctrl+C to stop")
httpd.serve_forever()
