# Safari Cross-Extension Script Injection PoC

## Vulnerability

Safari's `<all_urls>` host permission matches `webkit-extension://` URLs, allowing any extension with `<all_urls>` + `scripting` to inject JavaScript into other extensions' pages and steal their data.

**CVSS 3.1**: 9.1 (Critical)  
**Affected**: Safari 15.4+ (all platforms)  
**Chrome equivalent defense**: `permissions_data.cc:164-168`

## Structure

```
├── attacker-extension/     # "Dark Mode Pro" — steals data from other extensions
│   ├── manifest.json       # Requires <all_urls>, scripting, tabs
│   ├── background.js       # Scans for extension tabs, injects via executeScript
│   ├── popup.html          # Attack UI
│   └── popup.js            # Displays stolen data
├── victim-extension/       # "Secure Vault" — simulated password manager
│   ├── manifest.json       # Only requires storage
│   ├── background.js       # Stores fake credentials
│   ├── popup.html          # Vault display UI
│   └── popup.js            # Shows stored entries
├── REPORT.md               # Full English vulnerability report
└── REPORT_CN.md            # Full Chinese vulnerability report
```

## Reproduction

### Prerequisites

- macOS with Xcode
- Safari > Settings > Advanced > "Show features for web developers" enabled
- Safari > Develop menu > "Allow Unsigned Extensions" enabled

### Build Extensions

```bash
# Build victim extension
cd victim-extension
xcrun safari-web-extension-converter . --project-location ../xcode-victim --macos-only
# Open ../xcode-victim in Xcode → Build & Run

# Build attacker extension
cd ../attacker-extension
xcrun safari-web-extension-converter . --project-location ../xcode-attacker --macos-only
# Open ../xcode-attacker in Xcode → Build & Run
```

### Run Attack

1. Enable both extensions in Safari > Settings > Extensions
2. Click the victim extension ("Secure Vault") toolbar icon to open its popup
3. Click the attacker extension ("Dark Mode Pro") toolbar icon
4. Click "Scan & Steal Extension Data"
5. Observe: attacker displays all credentials stored by victim

### Expected vs Actual

| | Chrome | Safari |
|---|---|---|
| `scripting.executeScript` targeting other extension | Permission denied | **Code executes** |
| `<all_urls>` matches `*-extension://` | No | **Yes** |
| Cross-extension data isolation | Enforced | **Broken** |

## Root Cause

1. `WebExtensionMatchPattern.cpp:62` — `supportedSchemes()` includes `Scheme::Extension`
2. `WebExtensionContext.cpp:846` — `permissionState()` has no cross-extension deny rule
3. `WebExtensionContextAPIScriptingCocoa.mm:142` — `executeScript` trusts permission state without additional check

## Impact

A single malicious extension (disguised as a utility) can read ALL data from:
- Password managers (1Password, Bitwarden, LastPass)
- Crypto wallets (MetaMask, Phantom)
- Developer tools (GitHub, GitLab OAuth tokens)
- Any extension using `browser.storage`
