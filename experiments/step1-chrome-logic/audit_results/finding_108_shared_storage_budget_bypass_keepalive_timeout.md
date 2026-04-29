# Finding 108: Shared Storage selectURL Page Budget Bypassed During Keep-Alive Timeout

## Severity: MEDIUM

## Location
- `content/browser/shared_storage/shared_storage_worklet_host.cc`, lines 568-590

## Description

When a Shared Storage worklet is destructed while there are still unresolved URN mappings (i.e., the keep-alive timeout is reached), the code resolves them with `use_page_budgets=false` and `budget_remaining=0.0`:

```cpp
// If the worklet is destructed and there are still unresolved URNs (i.e. the
// keep-alive timeout is reached), consider the mapping to be failed.
auto it = unresolved_urns_.begin();
while (it != unresolved_urns_.end()) {
    // ...
    CreateSharedStorageURNMappingResult(
        storage_partition_, browser_context_, page_.get(),
        main_frame_origin_, shared_storage_origin_,
        shared_storage_site_, std::move(it->second),
        /*index=*/0, /*use_page_budgets=*/false,
        /*budget_remaining=*/0.0, budget_status);
```

While this resolves to index=0 (the default URL), the `use_page_budgets=false` parameter means the per-page and per-site budget checks (`CheckAndMaybeDebitSelectURLBudgets`) are completely skipped.

Similarly, at line 1619, when a saved query is found in the cache, `use_page_budgets=false` is passed:

```cpp
shared_storage_manager_->GetRemainingBudget(
    shared_storage_site_,
    base::BindOnce(&SharedStorageWorkletHost::
                       OnRunURLSelectionOperationOnWorkletFinished,
                   weak_ptr_factory_.GetWeakPtr(), urn_uuid,
                   select_url_start_time, execution_start_time, operation_id,
                   operation_name,
                   /*saved_query_name_to_cache=*/std::u16string(),
                   /*script_execution_succeeded=*/true,
                   /*script_execution_error_message=*/std::string(), index,
                   /*use_page_budgets=*/false));
```

## Impact

The per-page budget limit (`kSharedStorageSelectURLBitBudgetPerPageLoad` = 12.0 bits) and per-site budget limit (`kSharedStorageSelectURLBitBudgetPerSitePerPageLoad` = 6.0 bits) are privacy-critical controls. The `use_page_budgets=false` path in the saved query flow means that cached query results bypass these page-level budget controls entirely.

While the site-level navigation budget (`GetRemainingBudget`) is still checked, the page-level budgets are designed to provide an additional layer of protection against information leakage within a single page load. The saved query path lets an attacker use previously computed selectURL results without decrementing the page budget.

## Exploit Scenario

1. A site uses Shared Storage selectURL with saved queries enabled
2. The first call to selectURL with a given query name deducts from the page budget and caches the result
3. Subsequent calls to selectURL with the same saved query name bypass the page budget check (`use_page_budgets=false`)
4. This allows more information to be extracted via fenced frames than the page-level budget intended to allow

## References
- `content/browser/shared_storage/shared_storage_features.h` -- budget feature definitions
- `content/browser/renderer_host/page_impl.cc:439` -- CheckAndMaybeDebitSelectURLBudgets implementation
