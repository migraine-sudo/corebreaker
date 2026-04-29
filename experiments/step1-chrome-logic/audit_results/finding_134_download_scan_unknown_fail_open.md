# Finding 134: SafeBrowsing Download Scan Failure Treated as Not Dangerous (Fail-Open)

## Summary

When SafeBrowsing download scanning returns `DownloadCheckResult::UNKNOWN` (scan failure), Chrome treats the download as `DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS`. Failed scans fail open — a download that couldn't be scanned is allowed through without any warning.

## Affected Files

- `chrome/browser/download/chrome_download_manager_delegate.cc:516-518` — UNKNOWN → NOT_DANGEROUS mapping

## Details

```cpp
// chrome_download_manager_delegate.cc:516-518
case safe_browsing::DownloadCheckResult::UNKNOWN:
  // Failed scans with an unknown result should fail-open, so treat them as
  // if they're not dangerous.
  return download::DOWNLOAD_DANGER_TYPE_NOT_DANGEROUS;
```

When a SafeBrowsing scan fails (network error, service unavailable, timeout, etc.), the result is `UNKNOWN`. This is explicitly mapped to `NOT_DANGEROUS`, allowing the download to proceed without warning.

## Attack Scenario

1. Attacker distributes malware via download
2. They also run a DoS/interference attack against SafeBrowsing service or the user's connection to it
3. The download scan fails, returning `UNKNOWN`
4. Chrome treats the download as safe
5. User opens the malware without any SafeBrowsing warning

### Alternative: Timing-Based

1. Attacker serves download during known SafeBrowsing infrastructure maintenance windows
2. Or: attacker's page uses resource exhaustion to slow the SafeBrowsing check
3. Scan times out, returns `UNKNOWN`
4. Download proceeds as safe

## Impact

- **No compromised renderer required**: Standard download + SafeBrowsing interference
- **Malware delivery**: Bypasses SafeBrowsing download protection
- **Silent**: No warning shown to user for failed scans
- **By design**: The comment explicitly acknowledges the fail-open behavior

## VRP Value

**Medium** — By design, but the fail-open behavior for security scanning is concerning. Enterprise environments with `BLOCKED_SCAN_FAILED` handling have better protection, but consumer Chrome fails open.
