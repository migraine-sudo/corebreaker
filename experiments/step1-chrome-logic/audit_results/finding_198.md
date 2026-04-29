# Finding 198: Content Verification Uses DumpWithoutCrashing for Extension Root Path Mismatch

## Summary
In `ContentVerifyJob::StartWithContentHash`, when the hash's extension root path does not match the verify job's extension root path, the code calls `DumpWithoutCrashing()` but continues execution. This means the content verification proceeds with mismatched paths -- the file being read comes from one extension directory while the hashes used for verification come from a different directory. This could allow a corrupted extension directory to pass content verification if the hash file corresponds to a different (non-corrupted) version of the extension.

## Affected Files
- `extensions/browser/content_verifier/content_verify_job.cc` (lines 244-263)

## Details

```cpp
// The below detects if the hash and the verify jobs' extension roots don't
// match. If they don't then the hash comparison done later could match
// against a different extension root folder that could have different hashes.
// This could happen if this verify job was created before a corruption
// repair, but started after a corruption repair which was waiting until the
// extension went idle. This job would then have an extension root of
// .../<extension_version>_N and the `ContentHash` would have an extension
// root of .../<extension_version>_(N+1). The corrupted
// .../<extension_version>_N folder could still exist, and still have the same
// files (until it's garbage collected at some point) so the file's hash in
// the corrupted folder wouldn't match `content_hash`.
// TODO(crbug.com/416484593): Remove crash keys once we're confident the
// issue is fixed.
if (content_hash->extension_root() != extension_root_) {
  debug::ScopedContentVerifyJobCrashKey crash_keys(
      content_hash->extension_root(), extension_root_,
      content_hash->extension_id(), extension_id_,
      content_hash->extension_version(), extension_version_);
  base::debug::DumpWithoutCrashing();
}

// Fetch expected hashes.
hashes_ = ReadContentHashes(relative_path_, content_hash);
```

After the `DumpWithoutCrashing()` call, execution continues to `ReadContentHashes()`. The hashes are fetched from `content_hash` (which has a different extension root path), but the actual file content being verified comes from `extension_root_` (the verify job's path).

The comment explains the scenario: during corruption repair, the extension is re-installed to a new directory (e.g., `_N+1`), but the verify job was created pointing at the old directory (`_N`). The hash now corresponds to the new directory, not the old one.

The implications:
1. **Verification with wrong hashes**: Files from directory `_N` are verified against hashes from directory `_N+1`. If the corruption repair changed any files, the verification will fail (good). But if the corruption only affected files not in the current verification job, the mismatched verification could pass.
2. **Race window**: Between the verify job creation and the hash fetch, the extension root could change. The old directory (`_N`) could contain different content than what the hashes expect.
3. **DumpWithoutCrashing is a no-op in practice**: It reports the issue via crash reporting but does not stop the verification from proceeding with mismatched paths.

## Attack Scenario
1. An extension is installed and its content hashes are computed for directory `<version>_1`.
2. An attacker (or malware with local file access) modifies a file in the extension's `<version>_1` directory.
3. Chrome detects the corruption and initiates a repair, reinstalling to `<version>_2` with correct hashes.
4. A verify job was already created for `<version>_1` (e.g., for a resource being loaded from the extension).
5. The verify job starts and fetches hashes from `<version>_2` (the new, repaired directory).
6. The hash for the modified file in `<version>_1` does not match the hash from `<version>_2`, so the verification correctly fails for that file.
7. However, for other files in `<version>_1` that were not modified by the attacker, the hashes from `<version>_2` match, and verification passes.
8. The attacker's modified file fails verification, but the `DumpWithoutCrashing()` only reports the path mismatch -- it does not prevent other files from being served.

More critically:
9. If an attacker modifies a file and simultaneously triggers a corruption repair, there's a window where the old directory's content is served but verified against mismatched hashes, potentially in a way that produces false positives or false negatives depending on the timing.

## Impact
Low. Local file modification is generally outside Chrome's security model. However, the content verification system is specifically designed to detect tampered extension files, and proceeding with mismatched paths weakens this defense. The `DumpWithoutCrashing()` indicates this is a known issue being tracked (crbug.com/416484593).

## VRP Value
Low
