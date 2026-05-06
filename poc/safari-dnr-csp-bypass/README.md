# PoC: Safari declarativeNetRequest CSP Bypass via Unrestricted URL Scheme Redirect

## Quick Start (交互式演示)

```bash
# 1. 启动演示服务器
cd test-server
python3 demo_server.py

# 2. 在 Safari 中接受自签名证书：
#    访问 https://localhost:8443/demo，点击"访问此网站"

# 3. 先不启用扩展，观察正常状态：
#    页面显示 "✓ 脚本正常加载，没有被篡改"

# 4. 加载 PoC 扩展：
#    - Safari > 开发 > 允许未签名的扩展
#    - Safari > 设置 > 扩展 > 启用 "DNR CSP Bypass PoC"

# 5. 刷新 https://localhost:8443/demo
#    如果存在漏洞：页面显示被窃取的 cookies、API 数据
#    如果已修补：页面停留在 "等待脚本加载..."

# 6. 查看攻击者接收端：
#    https://localhost:8443/demo/attacker/log
#    显示被回传的所有窃取数据

# 7. 测试密码窃取：
#    https://localhost:8443/demo/login
#    密码管理器自动填充的凭据会被注入脚本读取
```

## 演示页面

| URL | 用途 |
|-----|------|
| `/demo` | 模拟银行页面 —— 展示 cookie 窃取、API 调用 |
| `/demo/login` | 模拟登录页 —— 展示密码自动填充窃取 |
| `/demo/attacker/log` | 攻击者数据接收端 —— 查看所有被窃取的数据 |
| `/demo/normal-extension-test` | 正常扩展行为说明 |

## 权限对比

### 没有漏洞时（declarativeNetRequest 正常能力）：
- ✓ 拦截/阻止网络请求
- ✓ HTTP → HTTPS 升级
- ✗ **不能**读取页面内容
- ✗ **不能**执行 JavaScript
- ✗ **不能**读取 Cookie
- ✗ **不能**访问密码
- ✗ **不能**开启摄像头

### 利用漏洞后（同一权限级别）：
- ☠ 任意 JavaScript 执行
- ☠ 读取所有 Cookie（会话劫持）
- ☠ 读取密码管理器自动填充的密码
- ☠ 以用户身份调用后端 API（转账、改密码）
- ☠ 如果用户之前授权过摄像头 → 静默录制
- ☠ 持续追踪地理位置
- ☠ 供应链攻击：一条规则影响数千网站

## Files

```
extension/
├── manifest.json             # MV3 extension, only "declarativeNetRequest" permission
├── rules.json                # Static redirect rule (regexSubstitution → data: URL)
├── background.js             # Service worker (logging only)
└── dynamic_rules_payload.js  # Demo of post-install dynamic rule injection

test-server/
├── demo_server.py            # 交互式演示服务器（推荐使用）
└── server.py                 # 简单验证服务器（原始版本）
```

## What This Proves

The extension has ONLY `declarativeNetRequest` permission — no host permissions, no
content script access, no `<all_urls>`, no `scripting` permission. Despite this minimal
permission set, it achieves arbitrary JavaScript execution on a CSP-protected page,
including cookie theft, password harvesting, and authenticated API abuse.
