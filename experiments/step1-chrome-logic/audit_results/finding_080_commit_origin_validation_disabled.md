# Finding 080: Commit Origin Validation Disabled (kValidateCommitOriginAtCommit)

## Summary

`kValidateCommitOriginAtCommit` is DISABLED by default. When disabled, `ValidateCommitOrigin()` is not called during navigation commit, meaning the browser does not verify that the origin used at commit time matches the expected origin from the FrameNavigationEntry. This can lead to session history corruption and origin isolation violations.

## Affected Files

- `content/public/common/content_features.cc:1119-1128` — Flag DISABLED_BY_DEFAULT
- `content/browser/renderer_host/navigation_request.cc:6686-6688` — ValidateCommitOrigin gated

## Details

```cpp
// navigation_request.cc:6686-6688
if (base::FeatureList::IsEnabled(features::kValidateCommitOriginAtCommit)) {
    ValidateCommitOrigin(origin_to_commit);  // DEAD CODE — flag disabled
}
```

The comment on the feature explains:
> Enables a CHECK in NavigationRequest::ValidateCommitOrigin() to verify
> that the origin used at commit time matches the expected origin stored
> in the FrameNavigationEntry, whenever PageState is non-empty.
>
> This helps catch session history corruption or stale origin-related state
> being sent to the renderer, which could violate origin isolation and lead
> to security issues (see crbug.com/41492620).

## Relationship to Other Findings

This is the complementary browser-side flag to Finding 055 (PageState origin mismatch with NotFatalUntil::M140). Together:
- Finding 055: PageState not cleared on origin mismatch (CHECK deferred to M140)
- Finding 080: ValidateCommitOrigin not called at all (flag disabled)

Both contribute to the same risk: stale origin-related state (PageState containing form data, scroll positions) being sent to the wrong origin.

## Impact

- **Requires compromised renderer or session history corruption**: Exploitation needs a state where FrameNavigationEntry has a stale origin
- **Origin isolation violation**: Wrong origin can receive PageState from another origin
- **Known issue**: crbug.com/41492620

## VRP Value

**Low-Medium** — This is a defense-in-depth measure being gradually rolled out. The direct security impact depends on triggering the stale state condition.
