# Finding 087: IWA Update Manifest URL Validation Uses NotFatalUntil::M138

## Summary

The `IsolationData` class validates update manifest URLs with `CHECK(..., base::NotFatalUntil::M138)`. Before Chrome M138, an invalid `update_manifest_url` can be stored and used for fetching updates without crashing.

## Affected Files

- `chrome/browser/web_applications/isolated_web_apps/isolation_data.cc:48-49,219,226` — NotFatalUntil::M138

## Details

```cpp
// isolation_data.cc:48-49
CHECK(!update_manifest_url_.has_value() || update_manifest_url_->is_valid(),
      base::NotFatalUntil::M138);
```

The URL is later used by `IsolatedWebAppUpdateDiscoveryTask` to fetch update manifests.

## Attack Scenario

1. Attacker corrupts the Web App database (local privilege escalation or filesystem manipulation)
2. Writes an attacker-controlled URL as `update_manifest_url`
3. On pre-M138 builds, the CHECK doesn't crash
4. Chrome fetches update manifests from the attacker's server
5. Could potentially serve malicious updates if combined with other vulnerabilities

## Impact

- **Requires local access**: Database corruption needed
- **Time-bounded**: Only affects pre-M138 builds
- **Update hijacking potential**: Misdirected update manifest fetches

## VRP Value

**Low** — Requires local access for database corruption. Limited time window.
