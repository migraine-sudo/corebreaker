# Finding 052: Service Worker Update Check Does Not Upgrade Insecure Requests

## Summary

During Service Worker script update checks, the `upgrade_if_insecure` flag on the network request is not set. This means if a SW was originally registered over HTTP and the site later migrated to HTTPS with `Upgrade-Insecure-Requests` CSP, the update check still fetches the script over HTTP. A network attacker could inject a malicious SW script during the update.

## Affected Files

- `content/browser/service_worker/service_worker_single_script_update_checker.cc:165-166` — Missing upgrade_if_insecure

## Details

### The TODO

```cpp
// service_worker_single_script_update_checker.cc:165-166
// Upgrade the request to an a priori authenticated URL, if appropriate.
// https://w3c.github.io/webappsec-upgrade-insecure-requests/#upgrade-request
// TODO(crbug.com/40637521): Set |ResourceRequest::upgrade_if_insecure_|
// appropriately.
```

The `upgrade_if_insecure` flag is never set on the update request. This means:
- If the original SW was registered at `http://example.com/sw.js`
- And the site now serves with `Content-Security-Policy: upgrade-insecure-requests`
- The update check will still fetch `http://example.com/sw.js` over plain HTTP
- A MITM attacker can inject a malicious script during the update

## Attack Scenario

### Service Worker poisoning via HTTP downgrade

1. User visits `https://example.com` (now HTTPS-only with `upgrade-insecure-requests`)
2. The site has an old SW registration from when it was HTTP: `http://example.com/sw.js`
3. Browser checks for SW updates — fetches `http://example.com/sw.js` over HTTP (no upgrade)
4. Network attacker (coffee shop WiFi, ISP, etc.) intercepts the HTTP request
5. Attacker serves a malicious SW script: `self.addEventListener('fetch', e => e.respondWith(attackerResponse()))`
6. Browser installs the malicious script as the updated SW
7. Malicious SW now intercepts ALL navigations and fetches for `example.com`
8. Even though the site migrated to HTTPS, the SW update path is still over HTTP

## Impact

- **No compromised renderer required**: This is a network-level attack
- **Persistent compromise**: Malicious SW persists in cache, survives page reloads
- **Full traffic interception**: Installed SW can read/modify all requests
- **Bypasses HTTPS migration**: Sites that migrated from HTTP to HTTPS are still vulnerable

## VRP Value

**Medium** — Requires MITM position + HTTP-registered SW (increasingly rare as sites migrate to HTTPS). But for affected sites, the impact is full traffic interception via persistent SW compromise.
