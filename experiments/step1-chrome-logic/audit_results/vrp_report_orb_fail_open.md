# VRP Report: ORB (Opaque Response Blocking) Fails Open by Skipping Spec Steps 10-16

## Title

ORB implementation skips critical spec steps and returns kAllow instead of kBlock at step 16 — Spectre mitigation gap

## Severity

Medium (Spectre mitigation weakness)

## Component

Internals > Network > OpaqueResponseBlocking

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions with ORB enabled.

## Summary

Chromium's ORB (Opaque Response Blocking) implementation intentionally skips steps 10, 11, 13, 15, and 16 of the ORB specification. At the critical step 16 — the default blocking step — the implementation returns `kAllow` instead of `kBlock`. This means cross-origin opaque responses that the ORB spec mandates should be blocked are instead allowed into the renderer process.

ORB is a **Spectre mitigation**: its purpose is to keep cross-origin response bytes out of renderer processes where microarchitectural side channels could read them. The fail-open design defeats this purpose.

## Affected Code

```cpp
// services/network/orb/orb_impl.cc:461-482
// TODO(lukasza): Implement the following steps from ORB spec:
// 10. If nosniff is true, then return false.
// 11. If response's status is not an ok status, then return false.
// (Skipping these steps minimizes the risk of shipping the initial ORB
// implementation.)

// Diff: Removing step 13:
//     13. If mimeType's essence starts with "audio/", "image/", or "video/",
//          then return false.

// Diff: Skipping/ignoring step 15:
//     15. If response's body parses as JavaScript and does not parse as JSON,
//         then return true.
// Diff: Changing step 16 to fail open (e.g. return true / kAllow):
//     16. Return false.
return Decision::kAllow;
```

## Steps to Reproduce

### 1. Set up a cross-origin API endpoint

At `https://api.target.example/user/data`:
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Content-Type-Options: nosniff

{"user": "victim", "email": "victim@example.com", "ssn": "123-45-6789"}
```

### 2. Attacker page at `https://evil.example/attack.html`

```html
<!DOCTYPE html>
<html>
<body>
<script>
// Make an opaque (no-cors) request to the API
// Response data enters the renderer process despite ORB
fetch('https://api.target.example/user/data', {
  mode: 'no-cors'
}).then(response => {
  // The response is opaque - we can't read it via JS
  // But the response bytes ARE in our process memory
  console.log('Response in memory (opaque):', response.type);
  
  // At this point, Spectre gadgets could read the JSON data
  // from the renderer process memory
});
</script>
</body>
</html>
```

### Expected Result (per ORB spec)

The response should be **blocked** at multiple points:
- Step 10: `nosniff` is set → block
- Step 16: Default → block

The response bytes should never enter the renderer process.

### Actual Result

The response is **allowed** into the renderer process:
- Step 10: Skipped
- Step 11: Skipped
- Step 13: Skipped
- Step 15: Skipped
- Step 16: Changed from `kBlock` to `kAllow`

The JSON data is in the renderer process memory, accessible to Spectre attacks.

## Root Cause

The ORB implementation chose a "fail-open" strategy to "minimize the risk of shipping the initial ORB implementation." Steps 10-16 are the defense-in-depth catch-all that blocks responses not matching earlier positive-allow rules. By skipping these steps, any response that isn't caught by earlier specific checks passes through.

### Additional weakness: Error handling

```cpp
// features.cc:137-138
BASE_FEATURE(kOpaqueResponseBlockingErrorsForAllFetches,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

When ORB does block a response, it injects an empty response instead of a network error (for script-initiated fetches). The spec mandates network errors.

## Security Impact

1. **Spectre mitigation gap**: Cross-origin response data enters renderer processes where it shouldn't
2. **No compromised renderer needed**: Standard `fetch()` with `mode: 'no-cors'`
3. **Exploitation requires Spectre**: Reading the opaque response data requires microarchitectural side channels
4. **Wide attack surface**: Any JSON API, any server that sets `nosniff`, any non-2xx responses

## Suggested Fix

1. Implement steps 10 and 11 (nosniff blocking, non-ok status blocking) — these are simple header checks
2. Implement step 13 (media MIME type blocking)
3. Implement step 16 as `kBlock` (default-deny)
4. Enable `kOpaqueResponseBlockingErrorsForAllFetches` by default

## PoC

Inline above. The key observation: cross-origin `no-cors` fetch responses with `nosniff` and JSON content-type are allowed into the renderer process despite the ORB spec requiring they be blocked.
