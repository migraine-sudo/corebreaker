# Finding 105: VerifyDidCommitParams Non-Enforcing — Renderer Can Lie About Commit State

## Summary

The `VerifyThatBrowserAndRendererCalculatedDidCommitParamsMatch` function compares browser-calculated values against renderer-supplied values for critical navigation parameters (method, URL, origin, status code, history behavior), but mismatches only trigger `DumpWithoutCrashing`, never renderer kills. In release builds, most non-origin parameter checks are disabled by default.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:18166-18496` — VerifyDidCommitParams
- `content/browser/renderer_host/render_frame_host_impl.cc:5349-5355` — Browser uses renderer values

## Details

```cpp
// render_frame_host_impl.cc:18166+
// Verification of: method, url_is_unreachable, post_id,
// is_overriding_user_agent, http_status_code, should_update_history,
// url, did_create_new_entry, transition, history_list_was_cleared, origin

// But when mismatches found:
// Line 18496:
base::debug::DumpWithoutCrashing();
// NOT: bad_message::ReceivedBadMessage(...)
```

Key facts:
- When `DCHECK_IS_ON()` is false (release builds), behind `features::kVerifyDidCommitParams`
- Even when enabled, only `DumpWithoutCrashing` on mismatch
- Individual param checks can be disabled via field trial params
- Non-origin params checking disabled by default in release

The browser then uses these renderer-supplied values:
```cpp
// Line 5349-5355:
last_http_method_ = params.method;
last_post_id_ = params.post_id;
last_http_status_code_ = params.http_status_code;
```

## Attack Scenario

1. Compromised renderer sends `DidCommitNavigation` with forged `method`, `http_status_code`, `should_update_history`, etc.
2. Browser detects mismatch but only does DumpWithoutCrashing (if verification enabled at all)
3. Browser stores the renderer-supplied values as authoritative state
4. `last_http_method_` affects future security decisions (e.g., POST → GET transition handling)
5. `should_update_history` can manipulate session history
6. `did_create_new_entry` can affect back/forward navigation behavior

## Impact

- **Requires compromised renderer**: Yes
- **History manipulation**: Control which navigations create history entries
- **HTTP method spoofing**: Make browser think navigation used different HTTP method
- **Known design issue**: The entire VerifyDidCommitParams system is acknowledged as non-enforcing

## VRP Value

**Medium** — Requires compromised renderer, but the scope of forgeable parameters is very broad.
