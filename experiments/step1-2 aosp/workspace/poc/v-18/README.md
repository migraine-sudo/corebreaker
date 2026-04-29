# V-18+V-19: RingtonePlayer Confused Deputy PoC

## Vulnerability
SystemUI's RingtonePlayer exposes IRingtonePlayer Binder via AudioManager.getRingtonePlayer()
with NO permission check. The play() and getTitle() methods accept arbitrary content:// URIs
and process them with SystemUI's elevated privileges.

## Attack Vector
- play(uri): SystemUI opens arbitrary content:// URI via MediaPlayer (file read as SystemUI)
- getTitle(uri): SystemUI queries arbitrary ContentProvider for metadata (_display_name/title)

## Prerequisites
- ZERO permissions required
- No user interaction needed
- Works on any Android version with SystemUI RingtonePlayer

## Build & Run
1. Open in Android Studio or build with gradle
2. adb install app-debug.apk
3. Launch the app
4. Tap "Test getTitle()" or "Test play()" buttons
5. Check logcat: adb logcat -s RingtonePoC

## Expected Result (if vulnerable)
- getTitle() returns metadata from protected ContentProviders (contacts, SMS, etc.)
- play() triggers SystemUI to open arbitrary URIs with its privileges

## Files
- ConfusedDeputyActivity.java — Main PoC activity (reflection-based)
- poc_shell.sh — adb shell alternative using service call
