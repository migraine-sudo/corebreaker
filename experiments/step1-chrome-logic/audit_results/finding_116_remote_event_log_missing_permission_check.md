# Finding 116: Remote WebRTC Event Log Manager Missing Permission Validation

## Severity: LOW

## Location
- `chrome/browser/media/webrtc/webrtc_event_log_manager_remote.cc`, line 799
- Function: `WebRtcRemoteEventLogManager::SetUpDirectoryForRemoteBoundLogs()`

## Description

The `WebRtcRemoteEventLogManager` manages remote-bound WebRTC event logs that are written to disk and later uploaded. The `SetUpDirectoryForRemoteBoundLogs()` function creates the directory for storing log files but has an explicit TODO acknowledging missing permission validation:

```cpp
if (!base::DirectoryExists(remote_bound_logs_dir)) {
    LOG(ERROR) << "Path for remote-bound logs is taken by a non-directory.";
    return false;
} else if (!base::CreateDirectory(remote_bound_logs_dir)) {
    LOG(ERROR) << "Failed to create the local directory for remote-bound logs.";
    return false;
}

// TODO(crbug.com/40545136): Test for appropriate permissions.

return true;
```

This TODO (crbug.com/40545136) appears in multiple places throughout the remote event log manager code:
- Line 799: Missing permission check on directory
- Line 979: Missing validity check on log files
- Multiple references to missing retry behavior and upload scheduling refinement

Additionally, the `StartRemoteLogging()` function at line 424 accepts `render_process_id`, `session_id`, `max_file_size_bytes`, `output_period_ms`, and `web_app_id` parameters. The `max_file_size_bytes` is validated against `kMaxRemoteLogFileSizeBytes` (50MB), but a compromised renderer could potentially trigger logging for many peer connections simultaneously, each with up to 50MB:

```cpp
const size_t kMaxRemoteLogFileSizeBytes = 50000000u;  // 50MB per log
```

The kill-switch TODO at `webrtc_event_log_manager.h:506` also reveals:
```
// TODO(crbug.com/40545136): Remove this kill-switch.
```

## Impact

- Log files may be written with incorrect permissions, potentially readable by other users on a shared system
- A compromised renderer could trigger excessive log file creation, consuming disk space
- The 50MB limit per log multiplied by many concurrent peer connections could lead to significant disk consumption
- Upload behavior is not fully refined, potentially leaking WebRTC session data

## Exploitability

LOW -- Requires a compromised renderer to call `StartRemoteLogging()` repeatedly. The `AdditionalActiveLogAllowed()` check provides some protection against unlimited log creation. The missing permission check on the directory is a defense-in-depth gap but unlikely to be directly exploitable in typical desktop environments. The log files are stored in the browser's profile directory which has appropriate OS-level permissions.
