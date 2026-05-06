#!/usr/bin/env python3
"""
交互式演示服务器 —— 直观对比 declarativeNetRequest 正常权限 vs 漏洞利用后的权限。

使用方法：
  python3 demo_server.py

然后在 Safari 中访问：
  https://localhost:8443/demo          ← 主演示页面
  https://localhost:8443/demo/attacker ← 模拟攻击者接收数据的端点

演示流程：
  1. 先不启用扩展，观察"正常权限"下扩展能做什么（只能拦截请求）
  2. 启用 PoC 扩展，观察"漏洞利用后"能做什么（读 cookie、读密码、调 API...）
"""

import http.server
import ssl
import os
import sys
import json
import urllib.parse
from datetime import datetime

PORT = 8443
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

stolen_data = []

class DemoHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/demo":
            self.serve_demo_page()
        elif path == "/demo/login":
            self.serve_login_page()
        elif path == "/demo/api/secret":
            self.serve_secret_api()
        elif path == "/demo/allowed-script.js":
            self.serve_allowed_script()
        elif path == "/demo/attacker/log":
            self.serve_attacker_log()
        elif path == "/demo/normal-extension-test":
            self.serve_normal_extension_page()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        if self.path == "/demo/attacker/receive":
            length = int(self.headers.get("Content-Length", 0))
            body = self.requestHandler = self.rfile.read(length).decode()
            stolen_data.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "data": body
            })
            print(f"\n{'='*60}")
            print(f"[STOLEN DATA RECEIVED] {datetime.now().strftime('%H:%M:%S')}")
            print(f"{body[:500]}")
            print(f"{'='*60}\n")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def serve_demo_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session_token=eyJhbGciOiJIUzI1NiJ9.FAKE_SESSION; Path=/")
        self.send_header("Set-Cookie", "user_id=victim_user_12345; Path=/")
        # 严格 CSP：只允许来自自身的脚本
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src https://localhost:8443; style-src 'unsafe-inline'; connect-src https://localhost:8443; img-src *"
        )
        self.end_headers()
        self.wfile.write(DEMO_HTML.encode())

    def serve_login_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session_token=eyJhbGciOiJIUzI1NiJ9.FAKE_SESSION; Path=/")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src https://localhost:8443; style-src 'unsafe-inline'; connect-src https://localhost:8443"
        )
        self.end_headers()
        self.wfile.write(LOGIN_HTML.encode())

    def serve_secret_api(self):
        """模拟一个需要登录才能访问的 API（通过 cookie 认证）"""
        cookie = self.headers.get("Cookie", "")
        if "session_token" in cookie:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = json.dumps({
                "secret": "这是用户的私密数据：银行余额 ¥1,234,567",
                "email": "victim@example.com",
                "phone": "138-0000-1234",
                "address": "北京市朝阳区某某路123号"
            })
            self.wfile.write(data.encode())
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "unauthorized"}')

    def serve_allowed_script(self):
        """正常情况下应该加载的脚本 —— 会被恶意扩展重定向"""
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.end_headers()
        self.wfile.write(NORMAL_SCRIPT.encode())

    def serve_attacker_log(self):
        """查看攻击者收到的数据"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(ATTACKER_LOG_HTML.encode())

    def serve_normal_extension_page(self):
        """展示正常 declarativeNetRequest 扩展能做什么"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(NORMAL_EXT_HTML.encode())

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


NORMAL_SCRIPT = """
// 这是正常的脚本 —— 如果你看到这段执行，说明扩展没有拦截
document.getElementById("status").innerHTML = '<span style="color:#4CAF50">✓ 脚本正常加载，没有被篡改</span>';
document.getElementById("status-box").className = "card safe";
"""

DEMO_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>银行模拟页面 - DNR CSP Bypass 演示</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #0f0f1a; color: #e0e0e0; padding: 2em; line-height: 1.6; }
        h1 { color: #00d4ff; margin-bottom: 0.5em; }
        h2 { color: #ff9800; margin: 1.5em 0 0.5em; font-size: 1.2em; }
        .card { padding: 1.2em; margin: 1em 0; border-radius: 8px; border: 1px solid #333; }
        .info { background: #1a2a3a; border-color: #2d6f8f; }
        .safe { background: #1a3a1a; border-color: #2d8f2d; }
        .danger { background: #3a1a1a; border-color: #8f2d2d; }
        .warning { background: #3a3a1a; border-color: #8f8f2d; }
        .compare { display: grid; grid-template-columns: 1fr 1fr; gap: 1em; margin: 1em 0; }
        .compare-box { padding: 1em; border-radius: 8px; }
        .before { background: #1a3a1a; border: 1px solid #2d8f2d; }
        .after { background: #3a1a1a; border: 1px solid #8f2d2d; }
        code { background: #2a2a3a; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }
        .tag-safe { background: #2d8f2d; color: white; }
        .tag-danger { background: #8f2d2d; color: white; }
        ul { padding-left: 1.5em; }
        li { margin: 0.3em 0; }
        #status { font-size: 1.1em; font-weight: bold; }
        .secret-data { background: #1a1a2e; padding: 1em; margin: 0.5em 0; border-radius: 4px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; display: none; }
        a { color: #00d4ff; }
    </style>
</head>
<body>
    <h1>🏦 模拟银行网站</h1>
    <p style="color:#888">这个页面模拟一个有严格 CSP 保护的银行网站</p>

    <div class="card info">
        <strong>📋 页面安全策略 (CSP)：</strong><br>
        <code>script-src https://localhost:8443</code><br>
        <small>含义：只有来自本服务器的脚本才能执行。data: URL、内联脚本、外部域全部被禁止。</small>
    </div>

    <div class="card info" id="status-box">
        <strong>当前状态：</strong>
        <span id="status">⏳ 等待脚本加载...</span>
    </div>

    <h2>📊 权限对比：正常 vs 漏洞利用后</h2>

    <div class="compare">
        <div class="compare-box before">
            <strong><span class="tag tag-safe">正常</span> declarativeNetRequest 扩展能做的：</strong>
            <ul>
                <li>✓ 拦截/阻止网络请求</li>
                <li>✓ 把 HTTP 重定向到 HTTPS</li>
                <li>✓ 重定向到其他 HTTP/HTTPS URL</li>
                <li>✗ <strong>不能</strong>读取页面内容</li>
                <li>✗ <strong>不能</strong>执行 JavaScript</li>
                <li>✗ <strong>不能</strong>读取 Cookie</li>
                <li>✗ <strong>不能</strong>访问密码</li>
                <li>✗ <strong>不能</strong>调用页面的 API</li>
            </ul>
        </div>
        <div class="compare-box after">
            <strong><span class="tag tag-danger">漏洞利用后</span> 同一个扩展能做的：</strong>
            <ul>
                <li>☠ 在任意页面执行任意 JavaScript</li>
                <li>☠ 读取所有 Cookie（会话劫持）</li>
                <li>☠ 读取密码管理器自动填充的密码</li>
                <li>☠ 以用户身份调用后端 API</li>
                <li>☠ 读写 localStorage（窃取 JWT）</li>
                <li>☠ 修改页面内容（钓鱼）</li>
                <li>☠ 如果用户之前授权过摄像头 → 静默开启</li>
                <li>☠ 读取地理位置（如之前已授权）</li>
            </ul>
        </div>
    </div>

    <h2>🔴 实时攻击演示（需启用 PoC 扩展）</h2>

    <div class="card warning">
        <strong>如果扩展已启用且漏洞存在，下方会显示窃取到的数据：</strong>
    </div>

    <div id="attack-results">
        <div class="card" style="background:#1a1a2e">
            <em style="color:#666">（启用 PoC 扩展后刷新页面，这里会显示攻击结果）</em>
        </div>
    </div>

    <h2>📖 说明</h2>
    <div class="card info">
        <strong>如何体验：</strong><br>
        1. 当前状态（不启用扩展）：上方状态显示"脚本正常加载"<br>
        2. 启用 PoC 扩展后刷新：观察页面被注入恶意代码，数据被窃取<br>
        3. 查看 <a href="/demo/attacker/log">攻击者接收端</a> 看窃取到了什么数据<br><br>
        <strong>关键点：</strong>这个扩展在 Safari 权限面板中显示为"仅能拦截网络请求"，<br>
        用户完全不知道它实际上在执行代码、窃取数据。
    </div>

    <!-- 这个脚本从"允许的源"加载。正常情况下应该安全执行。
         但恶意扩展会把它重定向到 data: URL，注入攻击代码。 -->
    <script src="https://localhost:8443/demo/allowed-script.js"></script>
</body>
</html>
"""

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>登录 - 模拟银行</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f0f1a; color: #e0e0e0; padding: 2em; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-box { background: #1a1a2e; padding: 2em; border-radius: 12px; width: 350px; border: 1px solid #333; }
        h2 { color: #00d4ff; margin-bottom: 1em; text-align: center; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #444; border-radius: 6px; background: #0f0f1a; color: #eee; font-size: 1em; }
        button { width: 100%; padding: 12px; margin-top: 1em; background: #00d4ff; color: #000; border: none; border-radius: 6px; font-size: 1em; font-weight: bold; cursor: pointer; }
        .note { margin-top: 1em; font-size: 0.8em; color: #666; text-align: center; }
        #status { margin-top: 1em; padding: 0.5em; border-radius: 4px; display: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🏦 银行登录</h2>
        <form id="login-form">
            <input type="text" id="username" name="username" placeholder="用户名" value="admin@bank.com" autocomplete="username">
            <input type="password" id="password" name="password" placeholder="密码" value="SuperSecret123!" autocomplete="current-password">
            <button type="submit">登录</button>
        </form>
        <div id="status"></div>
        <p class="note">此页面模拟密码管理器已自动填充凭据的场景。<br>如果 PoC 扩展启用，注入的脚本会读取这些值。</p>
    </div>

    <!-- 会被扩展重定向的脚本 -->
    <script src="https://localhost:8443/demo/allowed-script.js"></script>
</body>
</html>
"""

ATTACKER_LOG_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>攻击者数据接收端</title>
    <style>
        body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 2em; }
        h1 { color: #ff0000; }
        .entry { background: #1a1a1a; padding: 1em; margin: 1em 0; border-left: 3px solid #f00; border-radius: 4px; white-space: pre-wrap; word-break: break-all; }
        .time { color: #888; font-size: 0.85em; }
        #no-data { color: #666; }
    </style>
    <script>
        function refresh() {
            // 简单轮询展示
            location.reload();
        }
        setInterval(refresh, 3000);
    </script>
</head>
<body>
    <h1>☠ 攻击者数据接收端</h1>
    <p style="color:#888">以下是恶意扩展通过 CSP 绕过窃取并回传的数据：</p>
    <hr style="border-color:#333">
    """ + (
        "".join(f'<div class="entry"><span class="time">[{d["time"]}]</span>\n{d["data"]}</div>' for d in stolen_data)
        if stolen_data else '<p id="no-data">暂无数据。启用 PoC 扩展后访问 /demo 或 /demo/login 触发攻击。</p>'
    ) + """
</body>
</html>
"""

NORMAL_EXT_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>正常扩展行为演示</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f0f1a; color: #e0e0e0; padding: 2em; }
        h1 { color: #00d4ff; }
        .card { padding: 1.2em; margin: 1em 0; border-radius: 8px; background: #1a2a3a; border: 1px solid #2d6f8f; }
        code { background: #2a2a3a; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>正常 declarativeNetRequest 扩展行为</h1>
    <div class="card">
        <strong>这个页面演示 declarativeNetRequest 的正常（设计中的）用途：</strong><br><br>
        ✓ 拦截广告请求（如 block doubleclick.net）<br>
        ✓ 将 HTTP 升级为 HTTPS<br>
        ✓ 将跟踪链接重定向到干净 URL<br><br>
        <strong>这些操作都不涉及：</strong><br>
        ✗ 读取页面内容<br>
        ✗ 执行任何代码<br>
        ✗ 访问用户数据<br><br>
        Safari 告诉用户：<code>"此扩展不能读取或修改网页内容"</code>
    </div>
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

        print(f"[+] Generated self-signed certificate")
        return True
    except ImportError:
        return False


def generate_cert_openssl():
    ret = os.system(
        f'openssl req -x509 -newkey rsa:2048 -keyout {KEY_FILE} -out {CERT_FILE} '
        f'-days 365 -nodes -subj "/CN=localhost" 2>/dev/null'
    )
    return ret == 0


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[*] Generating self-signed TLS certificate...")
        if not generate_self_signed_cert():
            if not generate_cert_openssl():
                print("[-] Failed to generate certificate.")
                sys.exit(1)

    server = http.server.HTTPServer(("localhost", PORT), DemoHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          DNR CSP Bypass - 交互式演示服务器                    ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  演示页面：  https://localhost:{PORT}/demo                      ║
║  登录页面：  https://localhost:{PORT}/demo/login                ║
║  攻击者端：  https://localhost:{PORT}/demo/attacker/log         ║
║                                                              ║
║  步骤：                                                       ║
║  1. 先访问 /demo，观察正常状态                                  ║
║  2. 启用 PoC 扩展                                             ║
║  3. 刷新 /demo，观察攻击效果                                    ║
║  4. 查看 /demo/attacker/log 看窃取了什么                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    print(f"[*] Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
