# Finding 183: FedCM Primary Frame DCHECK Guards Stripped in Release Builds

## Summary
Multiple security-relevant checks that verify the RenderFrameHost is in the primary main frame are implemented using `DCHECK()` instead of `CHECK()`. These assertions are stripped in release builds, meaning the conditions they guard are not enforced in production Chrome. This includes checks before showing the accounts dialog, before processing disconnect requests, and before user info requests.

## Affected Files
- `content/browser/webid/request_service.cc:1263` -- `DCHECK(render_frame_host().GetPage().IsPrimary())` before showing dialog
- `content/browser/webid/request_service.cc:1478` -- `DCHECK(render_frame_host().GetPage().IsPrimary())` in accounts dialog
- `content/browser/webid/request_service.cc:1863` -- `DCHECK(render_frame_host().IsInPrimaryMainFrame())` in RedirectTo
- `content/browser/webid/disconnect_request.cc:59` -- `DCHECK(main_frame->IsInPrimaryMainFrame())` in disconnect
- `content/browser/webid/user_info_request.cc:105` -- `DCHECK(main_frame->IsInPrimaryMainFrame())` in user info

## Details
For example, in `request_service.cc`:
```cpp
// RenderFrameHost should be in the primary page (ex not in the BFCache).
DCHECK(render_frame_host().GetPage().IsPrimary());
```

And in `disconnect_request.cc`:
```cpp
RenderFrameHost* main_frame = render_frame_host->GetMainFrame();
DCHECK(main_frame->IsInPrimaryMainFrame());
embedding_origin_ = main_frame->GetLastCommittedOrigin();
```

The comment at line 1263 acknowledges that the RFH might not be in the primary page (e.g., in BFCache), but uses DCHECK instead of CHECK, meaning in release builds the code continues even if the page is in BFCache or a non-primary frame tree.

Compare with the proper CHECK at line 334:
```cpp
if (!render_frame_host().GetPage().IsPrimary()) {
    // This should not be possible but seems to be happening...
    std::move(callback).Run(RequestTokenStatus::kError, ...);
    return;
}
```

## Attack Scenario
1. A page with an active FedCM session is placed into the back-forward cache (BFCache).
2. In release builds, the DCHECK at line 1263 is stripped.
3. If the cached page's RFH is somehow triggered (e.g., via a stale callback), the FedCM dialog would be shown for a non-primary page.
4. The `embedding_origin_` in disconnect_request.cc (line 60) would be derived from a cached frame, potentially wrong.
5. Permission checks using the incorrect embedding origin could grant or deny access incorrectly.

## Impact
- Non-primary frame pages could potentially interact with FedCM flows in release builds.
- Incorrect embedding origin derivation in disconnect/user-info flows.
- The inconsistency between DCHECK and CHECK for the same type of check suggests incomplete hardening.

## VRP Value
**Low** -- While the underlying issue (BFCache interaction with FedCM) is acknowledged in comments, the use of DCHECK instead of CHECK means the guard is absent in production. The practical exploitability is limited since reaching these code paths from a BFCached page would require specific timing conditions.
