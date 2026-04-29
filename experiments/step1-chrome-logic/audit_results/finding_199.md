# Finding 199: WebView Content Script Injection Race Condition Bypasses Owner Validation

## Summary
In `UserScriptLoader::SendUpdate`, there is a known race condition (crbug.com/40864752) where `WebViewRendererState` does not yet know about a newly created guest process. When this race occurs, the code silently skips the update instead of enforcing the ownership check, and the DCHECK that should verify the owner is found is non-enforcing in release. A more critical issue is that the TODO explicitly calls for upgrading this to a CHECK but it remains a DCHECK, meaning the owner validation is not enforced in release builds.

## Affected Files
- `extensions/browser/user_script_loader.cc` (lines 543-590)

## Details

```cpp
#if BUILDFLAG(ENABLE_GUEST_VIEW)
  // If the process only hosts guest frames, then those guest frames share the
  // same embedder/owner. In this case, only scripts from allowlisted hosts or
  // from the guest frames' owner should be injected.
  // Concrete example: This prevents a scenario where manifest scripts from
  // other extensions are injected into webviews.
  if (process->IsForGuestsOnly() &&
      !CanExecuteScriptEverywhere(browser_context_, host_id())) {
    // There is a race condition by which WebViewRendererState does not yet know
    // about the newly created process. Rather than crashing, do nothing.
    // TODO(crbug.com/40864752): Fix race condition.
    if (!WebViewRendererState::GetInstance()->IsGuest(
            process->GetDeprecatedID())) {
      return SendUpdateResult::kNoActionTaken;
    }

    // TODO(crbug.com/40864752): Fix race condition and replace this with a
    // CHECK:
    // CHECK(WebViewRendererState::GetInstance()->IsGuest(
    //     process->GetDeprecatedID()));

    std::string owner_host;
    bool found_owner = WebViewRendererState::GetInstance()->GetOwnerInfo(
        process->GetDeprecatedID(), /*owner_process_id=*/nullptr, &owner_host);
    DCHECK(found_owner);

    // Keep this check in sync with the approach and formatting in:
    // - UserScriptLoader's HostID
    // - ScriptContextSet's HostID
    // - GuestView's owner host
    switch (host_id().type) {
      case mojom::HostID::HostType::kExtensions:
      case mojom::HostID::HostType::kWebUi:
      case mojom::HostID::HostType::kControlledFrameEmbedder:
        if (owner_host != host_id().id) {
          return SendUpdateResult::kNoActionTaken;
        }
        break;
    }
  }
#endif
```

Three issues in this code:

1. **Race condition (first branch)**: When `WebViewRendererState` doesn't know about the process yet, the code returns `kNoActionTaken` instead of enforcing the owner check. This means user scripts that should be injected are silently skipped. However, if the race resolves the other way (the process is known but the state is stale), scripts might be injected into the wrong WebView.

2. **DCHECK-only owner verification**: `DCHECK(found_owner)` on line 567 is not enforced in release. If `GetOwnerInfo` fails to find the owner (returns false), `owner_host` would be empty. An empty `owner_host` would only match `host_id().id` if the host ID is also empty, which is unlikely. However, this is a gap in the validation chain.

3. **Missing default case**: The `switch` statement on `host_id().type` only handles `kExtensions`, `kWebUi`, and `kControlledFrameEmbedder`. There is no `default` case. If a new `HostType` is added in the future, scripts from that type would be injected into any WebView without owner checking.

The comment at line 548 states the explicit security goal: "This prevents a scenario where manifest scripts from other extensions are injected into webviews." The race condition undermines this goal.

## Attack Scenario
1. An extension creates a `<webview>` element and loads a web page in it.
2. Another extension (Extension B) has content scripts that match the URL loaded in the WebView.
3. Normally, the owner check would prevent Extension B's scripts from being injected into Extension A's WebView.
4. During the race window when `WebViewRendererState` has not yet registered the new guest process, the `IsGuest` check returns false.
5. The code takes the early return path (`kNoActionTaken`), which skips the injection.
6. However, if the race resolves in a specific order where the process IS known as a guest but the owner info is stale, and `found_owner` returns false (DCHECK-only in release):
   - `owner_host` is empty
   - The check `owner_host != host_id().id` would be true for any non-empty extension ID
   - The injection would be correctly blocked in this case
7. The primary risk is that the race condition causes timing-dependent behavior where scripts may or may not be injected based on process registration timing.

## Impact
Low-Medium. The race condition is explicitly acknowledged with a TODO to fix it. The security impact depends on the race resolution order -- in the worst case, content scripts from one extension could be injected into another extension's WebView during the race window. The DCHECK-only owner validation provides an additional gap.

## VRP Value
Low
