# Finding 019: DisplayMediaAccessHandler DLP Bypass — Missing Return After RejectRequest

## Severity: High (ChromeOS Only)

## Summary

`DisplayMediaAccessHandler::OnDlpRestrictionChecked()` in `chrome/browser/media/webrtc/display_media_access_handler.cc` is missing a `return` statement after calling `RejectRequest()` when DLP (Data Leak Prevention) check fails. This causes `AcceptRequest()` to unconditionally execute, which can auto-approve a queued second `getDisplayMedia()` request with the DLP-denied `media_id`, bypassing ChromeOS DLP policy.

## Affected File

- `chrome/browser/media/webrtc/display_media_access_handler.cc:789-793`

## Bug Code

```cpp
// Line 778-795
#if BUILDFLAG(IS_CHROMEOS)
void DisplayMediaAccessHandler::OnDlpRestrictionChecked(
    base::WeakPtr<WebContents> web_contents,
    const DesktopMediaID& media_id,
    bool is_dlp_allowed) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);

  if (!web_contents) {
    return;
  }

  if (!is_dlp_allowed) {
    RejectRequest(web_contents.get(),
                  MediaStreamRequestResult::DLP_PERMISSION_DENIED);
  }                                                          // ← Missing return!
  AcceptRequest(web_contents.get(), media_id);               // ← Always executes
}
#endif  // BUILDFLAG(IS_CHROMEOS)
```

## How It Works

### Normal Flow (Single Request)
When only one request is queued:
1. DLP check returns `is_dlp_allowed = false`
2. `RejectRequest()` pops the first request from queue and calls callback with error
3. Queue is now empty
4. `AcceptRequest()` runs, finds empty queue (line 651-655), returns early
5. **Result**: Request correctly rejected — no bug

### Exploit Flow (Two Queued Requests)
When two `getDisplayMedia()` requests are queued for the same tab:
1. First request proceeds through media picker, user selects a DLP-protected resource
2. DLP check returns `is_dlp_allowed = false`
3. `RejectRequest()` pops request #1, calls callback with DLP_PERMISSION_DENIED
4. `RejectRequest()` sees queue is not empty (line 636), calls `ProcessQueuedAccessRequest()` — starts processing request #2
5. **`AcceptRequest()` runs immediately** — takes the front of queue (now request #2)
6. `AcceptRequest()` calls `GetDevicesForDesktopCapture()` with the DLP-denied `media_id`
7. **Result**: Request #2 is auto-approved for the DLP-protected resource, **bypassing DLP**

### Key Functions

**`RejectRequest` (line 619)**:
```cpp
void DisplayMediaAccessHandler::RejectRequest(WebContents* web_contents,
                                              MediaStreamRequestResult result) {
  // ... error handling ...
  PendingAccessRequest& mutable_request = *mutable_queue.front();
  std::move(mutable_request.callback)
      .Run(blink::mojom::StreamDevicesSet(), result, /*ui=*/nullptr);
  mutable_queue.pop_front();                    // Removes request #1
  if (!mutable_queue.empty()) {
    ProcessQueuedAccessRequest(mutable_queue, web_contents);  // Starts request #2
  }
}
```

**`AcceptRequest` (line 641)**:
```cpp
void DisplayMediaAccessHandler::AcceptRequest(WebContents* web_contents,
                                              const DesktopMediaID& media_id) {
  // ... error handling ...
  PendingAccessRequest& pending_request = *queue.front();     // Now request #2!
  // ... proceeds to approve with DLP-denied media_id ...
}
```

## Attack Scenario

1. On ChromeOS with DLP policies configured to protect certain screen content
2. Attacker page calls `getDisplayMedia()` twice in quick succession
3. First call proceeds to media picker dialog, user selects a DLP-protected tab
4. DLP check rejects the first request (as expected)
5. But the second request is auto-approved with the same DLP-protected target
6. Attacker captures DLP-protected screen content

## Impact

- **DLP Bypass**: ChromeOS Data Leak Prevention policies are bypassed
- **Screen Capture**: Attacker captures content that is explicitly protected by enterprise policy
- **No User Interaction**: Second request is auto-approved without media picker dialog
- **Platform**: ChromeOS only (the code is within `#if BUILDFLAG(IS_CHROMEOS)`)

## Fix

```cpp
if (!is_dlp_allowed) {
    RejectRequest(web_contents.get(),
                  MediaStreamRequestResult::DLP_PERMISSION_DENIED);
    return;  // ← Add return here
}
AcceptRequest(web_contents.get(), media_id);
```

## Prerequisites

- ChromeOS device with DLP policies configured
- DLP policy that restricts screen sharing of certain content
- Two queued `getDisplayMedia()` requests from the same tab

## VRP Assessment

- **Severity**: High for ChromeOS enterprise environments
- **Known**: No TODO or crbug found for this specific bug
- **Code Age**: File is well-established but the DLP integration is newer
- **VRP Value**: Medium-High — DLP bypass is a real enterprise security concern on ChromeOS

## Discovery Method

Sub-agent systematic audit of WebRTC/MediaStream security code, focusing on control flow in error handling paths.
