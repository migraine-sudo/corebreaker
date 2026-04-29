# Finding 117: Desktop Capture Security Checks Bypassable via Command-Line Switches

## Severity: LOW

## Location
- `chrome/browser/media/webrtc/desktop_capture_access_handler.cc`, lines 250-267

## Description

The `DesktopCaptureAccessHandler::ProcessScreenCaptureAccessRequest()` function has multiple security checks that can be bypassed using command-line switches:

### 1. Screen Capture Enable Bypass
```cpp
const bool screen_capture_enabled =
    base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kEnableUserMediaScreenCapturing) ||
    pending_request->is_allowlisted_extension ||
    IsBuiltInFeedbackUI(pending_request->request.security_origin);
```

The `--enable-usermedia-screen-capturing` switch enables screen capture for all origins through the `getUserMedia()` API (as opposed to `getDisplayMedia()` which is the standard path).

### 2. HTTP Origin Security Bypass
```cpp
const bool origin_is_secure =
    network::IsUrlPotentiallyTrustworthy(
        pending_request->request.security_origin) ||
    base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kAllowHttpScreenCapture);
```

The `--allow-http-screen-capture` switch allows non-HTTPS origins to use screen capture, bypassing the secure context requirement.

### 3. Combined Effect

Together, these switches allow:
- Any HTTP page to capture the user's screen via `getUserMedia()` instead of `getDisplayMedia()`
- The `getUserMedia()` path through extension-based screen capture may have different (possibly weaker) dialog flows compared to `getDisplayMedia()`

## Impact

These are development/testing switches that should not be present in production builds. If a user or malware sets these command-line flags on a production Chrome installation, the security boundaries for screen capture are significantly weakened. The switches are:
- `--enable-usermedia-screen-capturing` -- enables legacy screen capture API
- `--allow-http-screen-capture` -- allows insecure origins to capture screens

## Exploitability

LOW -- These require modifying the Chrome command line at launch time, which requires local system access. However:
- Malware could create modified Chrome shortcuts with these flags
- MDM/enterprise deployment could accidentally set these
- Chrome kiosk or signage deployments might use these flags insecurely
- No runtime warning is displayed to the user when these flags are active

The user still sees a capture permission dialog (via `CheckIfRequestApproved()`), providing some defense-in-depth.
