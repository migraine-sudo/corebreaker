# Finding 225: Network Service Mojo Deserialization Errors Not Fatal in Official/Release Builds

## Summary

The network service's mojo bad message handler uses `DumpWithoutCrashing()` instead of `LOG(FATAL)` in official (release) builds. This means that when a mojo IPC message fails deserialization validation in the network service, the network service process continues running rather than terminating. In debug builds, the same condition is fatal (`LOG(FATAL)`).

This weakens the security boundary between renderers and the network service: a compromised renderer sending malformed mojo messages to the network service will cause crash reports to be uploaded, but the network service will continue processing potentially corrupted state.

## Affected Files

- `services/network/network_service.cc` lines 245-256:
  ```cpp
  // Also create dump instead of crash for builds without DCHECK on as some
  // fuzzing tests are done using builds without ENABLE_IPC_FUZZER, but those
  // builds are always with DCHECK disabled. As DCHECK is on for most builds,
  // we still have enough coverage for crashing upon bad message behavior.
  #if defined(OFFICIAL_BUILD) || defined(ENABLE_IPC_FUZZER) || !DCHECK_IS_ON()
    mojo::debug::ScopedMessageErrorCrashKey crash_key_value(error);
    base::debug::DumpWithoutCrashing();
    network::debug::ClearDeserializationCrashKeyString();
  #else
    LOG(FATAL) << error;
  #endif
  ```

## Code Snippet

```cpp
// network_service.cc:241-256
NetworkService::NetworkService(
    mojo::PendingReceiver<mojom::NetworkService> receiver,
    ...) {
  // ...
  mojo::SetDefaultProcessErrorHandler(
      base::BindRepeating([](const std::string& error) {
    // ...
    #if defined(OFFICIAL_BUILD) || defined(ENABLE_IPC_FUZZER) || !DCHECK_IS_ON()
      mojo::debug::ScopedMessageErrorCrashKey crash_key_value(error);
      base::debug::DumpWithoutCrashing();  // Process continues!
    #else
      LOG(FATAL) << error;  // Debug: process terminates
    #endif
  }));
  // ...
}
```

This error handler is the default for ALL mojo messages in the network service, including `ReportBadMessage` calls from `WebSocketFactory`, `CorsURLLoaderFactory`, `RestrictedCookieManager`, etc.

## Attack Scenario

1. A compromised renderer sends a malformed mojo message to the network service (e.g., an invalid enum value, an out-of-bounds struct field, etc.)
2. The mojo deserialization layer detects the error
3. In production Chrome: `DumpWithoutCrashing()` is called -- a crash report is sent to Google, but the network service continues running
4. The compromised renderer can probe the network service's mojo interface boundaries repeatedly without the network service being terminated
5. If any mojo deserialization error leaves the network service in a partially-corrupted state, the renderer can attempt to exploit that state in subsequent requests

Note: Individual `mojo::ReportBadMessage()` calls DO kill the connection (the mojo pipe is reset), but the network service process itself survives. The concern is with mojo-level deserialization errors that occur before message dispatch.

## Impact

- **Severity**: Low (defense-in-depth issue)
- **Requires compromised renderer**: Yes (sending malformed mojo messages)
- **Security principle violated**: Fail-closed; invalid inputs should terminate the affected process
- The comment explicitly acknowledges this is a trade-off for stability: "some fuzzing tests are done using builds without ENABLE_IPC_FUZZER"
- In practice, mojo deserialization errors should be rare in production, so the DumpWithoutCrashing provides useful crash reports
- However, this means a compromised renderer can probe mojo boundaries without being shut down

## VRP Value Rating

Low - This is an intentional design decision for production stability. The DumpWithoutCrashing still records the error for analysis. The individual `mojo::ReportBadMessage()` calls at the application layer properly reject and disconnect bad callers. This finding is primarily about the lower-level mojo deserialization error handler not being fatal.
