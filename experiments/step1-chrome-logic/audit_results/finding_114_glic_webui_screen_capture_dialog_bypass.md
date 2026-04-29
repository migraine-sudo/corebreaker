# Finding 114: chrome://glic WebUI Bypasses Screen Capture Selection Dialog

## Severity: LOW

## Location
- `chrome/browser/media/webrtc/display_media_access_handler.cc`, lines 91-133
- Function: `GetMediaForSelectionDialogBypass()`

## Description

The `DisplayMediaAccessHandler` contains a special bypass for `chrome://glic` (Google Lens Integration in Chrome) that skips the screen capture selection dialog entirely:

```cpp
bool IsGlicWebUI(const WebContents* web_contents) {
    return glic::IsGlicWebUI(web_contents);
}

DesktopMediaID GetMediaForSelectionDialogBypass(
    const HostContentSettingsMap& content_settings,
    WebContents* web_contents,
    const content::MediaStreamRequest& request) {
    // Only bypass for chrome:// URLs.
    if (web_contents->GetLastCommittedURL().GetScheme() != content::kChromeUIScheme) {
        return DesktopMediaID();
    }

    // Special behavior for chrome://glic: skip tab capture dialog.
    if (request.video_type == DISPLAY_VIDEO_CAPTURE_THIS_TAB &&
        IsGlicWebUI(web_contents)) {
        DesktopMediaID media_id(
            DesktopMediaID::TYPE_WEB_CONTENTS, DesktopMediaID::kNullId,
            WebContentsMediaCaptureId(...));
        media_id.audio_share = ...;
        return media_id;
    }
    // ...
}
```

And a second bypass path for system audio:
```cpp
} else if (request.video_type == MediaStreamType::NO_SERVICE &&
           request.audio_type != MediaStreamType::NO_SERVICE &&
           !request.exclude_system_audio &&
           content_settings.GetContentSetting(
               origin_url, origin_url,
               ContentSettingsType::DISPLAY_MEDIA_SYSTEM_AUDIO) ==
               ContentSetting::CONTENT_SETTING_ALLOW) {
    return DesktopMediaID(TYPE_SCREEN, kNullId, /*audio_share=*/true);
}
```

The `BypassMediaSelectionDialog()` function at line 381 has a secondary chrome:// scheme check, providing defense-in-depth. However:

1. The `IsGlicWebUI()` check delegates to `glic::IsGlicWebUI()` which may not be robust against all WebUI spoofing attacks
2. The system audio bypass relies on `ContentSettingsType::DISPLAY_MEDIA_SYSTEM_AUDIO` being set to ALLOW for the chrome:// origin
3. No transient user activation is checked in the bypass path

## Impact

If an attacker could navigate to or spoof a chrome://glic page context, they could capture the current tab's content and audio without the user seeing a screen capture selection dialog. The chrome:// scheme restriction limits the attack surface significantly.

## Exploitability

LOW -- The chrome:// scheme is not accessible to web content, and Chromium's security model prevents web content from loading chrome:// URLs. This finding would only be exploitable if:
1. There is a chrome:// URL spoofing vulnerability
2. A bug in `glic::IsGlicWebUI()` allows non-glic chrome:// pages to pass the check
3. An extension with chrome:// access could reach this code path

The defense-in-depth chrome:// scheme check in `BypassMediaSelectionDialog()` further limits exploitability.
