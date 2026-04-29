# Finding 167: Opaque Origin Subframes Bypass JS Dialog Suppression

## Summary

Chrome suppresses JavaScript dialogs (alert, confirm, prompt) from cross-origin subframes to prevent dialog spoofing. However, frames with opaque origins (sandboxed iframes) bypass this suppression entirely because the origin comparison check is skipped for opaque origins.

## Affected Files

- `content/browser/web_contents/web_contents_impl.cc:9111-9116` — Opaque origin bypass

## Details

```cpp
// web_contents_impl.cc:9111-9116
// We can't check for opaque origin cases, default to allowing them to
// trigger dialogs.
// TODO(carlosil): The main use case for opaque use cases are tests,
// investigate if there are uses in the wild, otherwise adapt tests that
// require dialogs so they commit an origin first, and remove this
// conditional.
if (!render_frame_host->GetLastCommittedOrigin().opaque()) {
  bool is_different_origin_subframe =
      render_frame_host->GetLastCommittedOrigin() !=
      render_frame_host->GetOutermostMainFrame()->GetLastCommittedOrigin();
  suppress_this_message |= is_different_origin_subframe;
```

When a frame has an opaque origin (e.g., a sandboxed iframe), the entire cross-origin dialog suppression check is skipped. The frame is allowed to show JS dialogs just like a same-origin frame.

## Attack Scenario

1. Attacker embeds a sandboxed iframe: `<iframe sandbox="allow-scripts allow-modals" src="https://attacker.com/phish">`
2. The sandboxed iframe has an opaque origin, bypassing the cross-origin dialog suppression
3. The iframe shows `window.prompt("Your session expired. Enter password to continue:")` 
4. The dialog appears to come from the parent page (the browser shows the parent's origin in the dialog header)
5. User enters credentials thinking they're for the parent site

### Alternative: Data URL iframe
1. `<iframe src="data:text/html,<script>alert('Session expired')</script>">`
2. Data URLs create opaque origins
3. Dialog suppression is bypassed

## Impact

- **No compromised renderer required**: Standard HTML/JavaScript
- **Dialog spoofing**: Cross-origin dialogs appear to come from the parent page
- **Phishing**: Can trick users into entering credentials
- **Known issue**: TODO comment acknowledges the gap

## VRP Value

**Medium** — Dialog spoofing from cross-origin iframes. The impact is phishing/social engineering. The TODO comment suggests Chrome is aware but hasn't fixed it. Browsers are supposed to suppress dialogs from cross-origin subframes (Chrome feature: https://www.chromestatus.com/feature/5148698084376576), but sandboxed iframes bypass this.
