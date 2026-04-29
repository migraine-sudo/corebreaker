# Finding 213: WebTransport Developer Mode Flag Disables Handshake Failure Penalties

## Summary

The `--webtransport-developer-mode` command-line flag completely disables the handshake failure penalty system for WebTransport connections. When this flag is set, `ShouldQueueHandshakeFailurePenalty()` returns false, and instead of queueing penalties (up to 5 minutes), failed handshakes simply decrement the pending count immediately. This flag is accessible via `chrome://flags` and is on the never-expire list, meaning it will persist across Chrome versions.

While the flag is intended for developers testing WebTransport, it can be enabled by any user and eliminates the DoS protection that throttling provides against aggressive WebTransport connection spam to unresponsive servers.

## Affected Files

- `content/browser/webtransport/web_transport_throttle_context.cc` lines 26-29:
  ```cpp
  bool ShouldQueueHandshakeFailurePenalty() {
    base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
    return !command_line ||
           !command_line->HasSwitch(switches::kWebTransportDeveloperMode);
  }
  ```
- `content/browser/webtransport/web_transport_throttle_context.cc` lines 310-322:
  ```cpp
  void WebTransportThrottleContext::MaybeQueueHandshakeFailurePenalty(
      const std::optional<net::IPAddress>& server_address) {
    if (should_queue_handshake_failure_penalty_) {
      auto penalty = base::Minutes(5);
      // ...
      penalty_mgr_.QueuePending(penalty);
      return;
    }
    // Developer mode: skip penalty entirely
    CHECK_GE(penalty_mgr_.PendingHandshakes(), 0);
    penalty_mgr_.RemovePendingHandshakes();
  }
  ```
- `chrome/browser/flag-never-expire-list.json` line 149:
  ```json
  "webtransport-developer-mode",
  ```
- `chrome/browser/about_flags.cc` line 4812

## Code Snippet

```cpp
// web_transport_throttle_context.cc
bool ShouldQueueHandshakeFailurePenalty() {
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  return !command_line ||
         !command_line->HasSwitch(switches::kWebTransportDeveloperMode);
}
```

## Attack Scenario

1. Social engineering: Attacker instructs users to enable `--webtransport-developer-mode` flag (e.g., via a "fix your connection" tutorial)
2. With the flag enabled, WebTransport handshake failure penalties are entirely disabled
3. A malicious page can now rapidly attempt WebTransport connections to local network hosts without exponential backoff
4. This enables faster local network scanning via WebTransport, bypassing the timing-based protection
5. The flag is on the never-expire list, so it persists across Chrome updates

Without developer mode, failed handshakes incur:
- First failure: 100ms penalty (per IP), 50ms (unknown server)
- Repeat failures to same IP: 5 minute penalty
- Repeat failures to same subnet: 2 minute penalty

With developer mode, all penalties are zero.

## Impact

- **Severity**: Low (requires user action to enable flag)
- **Requires compromised renderer**: No
- **Security principle violated**: Developer convenience flags should not disable security measures entirely
- The never-expire status means this flag is intended to be permanent
- Reduces protection against WebTransport-based port scanning of local networks

## VRP Value Rating

Low - Requires user action to enable the flag. However, the complete elimination of throttling penalties (rather than just reducing them) is more aggressive than necessary for developer usage. A better approach would be to reduce penalties but not eliminate them entirely.
