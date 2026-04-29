# Finding 048: Service Worker Main Script URL Not Verified (kServiceWorkerVerifyMainScriptUrl Disabled)

## Summary

The browser process does not verify that a Service Worker main script request URL matches the Service Worker's registered script URL. The fix (`ReportBadMessage("SWSLF_FORGED_MAIN_SCRIPT_REQUEST")`) exists but is gated behind `kServiceWorkerVerifyMainScriptUrl`, which is `FEATURE_DISABLED_BY_DEFAULT`. A compromised renderer can request an arbitrary script URL for a Service Worker, potentially loading a script from a different path or origin.

## Affected Files

- `content/browser/service_worker/service_worker_script_loader_factory.cc:208-214` — Script URL verification disabled
- `content/browser/service_worker/service_worker_new_script_loader.cc:109` — Same check in new script loader
- `content/browser/service_worker/service_worker_updated_script_loader.cc:80` — Same check in update loader
- `content/common/features.cc` — kServiceWorkerVerifyMainScriptUrl DISABLED_BY_DEFAULT

## Details

### The disabled check

```cpp
// service_worker_script_loader_factory.cc:208-214
if (resource_request.destination ==
        network::mojom::RequestDestination::kServiceWorker &&
    resource_request.mode == network::mojom::RequestMode::kSameOrigin &&
    resource_request.url != version->script_url()) {
  if (base::FeatureList::IsEnabled(
          features::kServiceWorkerVerifyMainScriptUrl)) {
    mojo::ReportBadMessage("SWSLF_FORGED_MAIN_SCRIPT_REQUEST");
    return false;  // DEAD CODE — flag disabled
  }
}
```

When the flag is disabled (default), a renderer that sends a script request with a URL different from the registered SW script URL is **not killed** and the request **proceeds**.

### Three affected code paths

The same disabled check appears in:
1. `service_worker_script_loader_factory.cc:210` — Initial script load
2. `service_worker_new_script_loader.cc:109` — New script installation
3. `service_worker_updated_script_loader.cc:80` — Script update

## Attack Scenario

### Service Worker script substitution (requires compromised renderer)

1. A compromised renderer registers a Service Worker for `https://victim.example/sw.js`
2. During script fetch, the renderer's loader factory receives the request
3. The compromised renderer modifies the request URL to `https://victim.example/attacker-controlled.js`
4. Browser does not verify the URL mismatch (check disabled)
5. The attacker-controlled script is loaded as the Service Worker
6. The SW now intercepts all fetch requests for `victim.example`'s scope

### SW update poisoning

1. Attacker compromises a renderer that has a registered SW
2. During SW update check, the request URL is changed to a malicious script
3. The malicious script is installed as the updated SW
4. Persists across browser restarts as the SW is installed in the cache

## Impact

- **Requires compromised renderer**: The renderer must forge the script URL in the IPC
- **Persistent compromise**: A malicious Service Worker persists in the cache
- **Scope escalation**: The attacker's script intercepts all requests within the SW scope
- **Three code paths**: All script loading paths have the same disabled check

## VRP Value

**Medium** — Requires compromised renderer but enables persistent compromise via malicious Service Worker installation. The explicit `ReportBadMessage` with a descriptive string confirms this is a known security concern.
