# Finding 043: ORB (Opaque Response Blocking) Fails Open by Skipping Critical Spec Steps

## Summary

Chromium's ORB implementation intentionally skips steps 10, 11, 13, 15, and 16 of the ORB specification. At step 16, instead of returning `kBlock` (blocking the response), the implementation returns `kAllow`. This means cross-origin opaque responses that should be blocked under the ORB spec are instead allowed through to the requesting context.

## Affected Files

- `services/network/orb/orb_impl.cc:461-482` — Steps 10-16 skipped, fail-open return
- `services/network/orb/orb_mimetypes.cc:158` — Missing `application/signed-exchange` in never-sniffed types
- `services/network/public/cpp/features.cc:137-138` — kOpaqueResponseBlockingErrorsForAllFetches DISABLED

## Details

### Skipped specification steps

```cpp
// orb_impl.cc:461-482
// TODO(lukasza): Implement the following steps from ORB spec:
// 10. If nosniff is true, then return false.
// 11. If response's status is not an ok status, then return false.
// (Skipping these steps minimizes the risk of shipping the initial ORB
// implementation.)

// TODO(lukasza): Departure from the spec discussed in
// https://github.com/annevk/orb/issues/3.
// Diff: Removing step 13:
//     13. If mimeType's essence starts with "audio/", "image/", or "video/",
//          then return false.

// TODO(lukasza): Departure from the spec, because the current implementation
// avoids full Javascript parsing as described in the "Gradual CORB -> ORB
// transition" doc at [...]
// Diff: Skipping/ignoring step 15:
//     15. If response's body parses as JavaScript and does not parse as JSON,
//         then return true.
// Diff: Changing step 16 to fail open (e.g. return true / kAllow):
//     16. Return false.
return Decision::kAllow;
```

### What each skipped step protects

| Step | Spec behavior | Chrome behavior | Impact |
|------|---------------|-----------------|--------|
| 10 | Block if `nosniff` header set | Skipped | Responses with `X-Content-Type-Options: nosniff` not blocked when they should be |
| 11 | Block if non-2xx status | Skipped | Error responses (4xx, 5xx) from cross-origin allowed through |
| 13 | Block audio/image/video MIME | Skipped | Media resources not blocked as opaque |
| 15 | Block if body parses as JS (not JSON) | Skipped | JS-parseable responses reach opaque context |
| 16 | Block (default) | **Changed to Allow** | Everything not caught by earlier steps passes through |

### Error handling also weakened

```cpp
// features.cc:137-138
BASE_FEATURE(kOpaqueResponseBlockingErrorsForAllFetches,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

When ORB does block a response, it injects an empty response rather than a network error (for script-initiated fetches). The spec mandates network errors. The flag to fix this is disabled.

## Attack Scenario

### Cross-origin data exfiltration via Spectre

ORB is a **Spectre mitigation**. Its purpose is to prevent cross-origin response data from entering a renderer process where Spectre gadgets could read it. With steps 10-16 not enforced:

1. Attacker page at `evil.example` makes an opaque `no-cors` request to `victim-api.example/user/data`
2. The response is `application/json` with `X-Content-Type-Options: nosniff` and contains sensitive user data
3. **Per ORB spec**: Step 10 would block (nosniff set), step 16 would block (default deny)
4. **Per Chrome implementation**: Steps 10 and 16 skipped — response data enters the renderer process
5. Spectre gadget in `evil.example`'s renderer can read the cross-origin response bytes from memory
6. User data exfiltrated

### JSON API data exposure

1. `victim-api.example` returns JSON API responses
2. Under the ORB spec, step 15 would check if the response parses as JavaScript but not JSON, and step 16 would block by default
3. Chrome skips both steps — JSON data enters the cross-origin renderer
4. Combined with side-channel attacks (Spectre, process memory scanning), data is readable

## Impact

- **Spectre mitigation gap**: ORB exists to keep cross-origin data out of processes that shouldn't see it. The fail-open design means data enters the renderer anyway.
- **No compromised renderer required**: The attack uses standard `fetch()` with `mode: 'no-cors'`. The data enters the renderer process via normal channel — exploitation requires a microarchitectural side-channel (Spectre).
- **Spec violation**: Chromium's ORB deviates from the W3C spec in multiple places, all in the direction of allowing data through.

## VRP Value

**Medium-High** — Requires Spectre or similar side-channel for full exploitation, but ORB is specifically designed as a Spectre mitigation. The fail-open design defeats the purpose of the entire mechanism. The explicit TODOs and spec deviation documentation suggest this is a known gap that hasn't been addressed.
