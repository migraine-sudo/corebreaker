# Finding 188: FedCM getUserInfo Returns All IdP Accounts Including Non-Returning Ones

## Summary
The `UserInfoRequest::MaybeReturnAccounts()` function returns data for ALL accounts from the IdP, not just the returning (previously consented) accounts. As long as at least one account is a returning account, the personal information (email, name, given name, picture) for every account in the IdP's response is returned to the requesting website. This enables information disclosure about accounts that the user never consented to share with this website.

## Affected Files
- `content/browser/webid/user_info_request.cc:243-291` -- `MaybeReturnAccounts()` returns all accounts if any is returning
- `content/browser/webid/user_info_request.cc:271-289` -- Comment confirms design: "Return data for all the IdP accounts"

## Details
```cpp
void UserInfoRequest::MaybeReturnAccounts(
    const std::vector<IdentityRequestAccountPtr>& accounts) {
  DCHECK(!accounts.empty());

  bool has_returning_accounts = false;
  for (const auto& account : accounts) {
    if (IsReturningAccount(*account)) {
      has_returning_accounts = true;
      break;
    }
  }
  // ...
  if (!has_returning_accounts) {
    CompleteWithError(/*...*/);
    return;
  }

  // The user previously accepted the FedCM prompt for one of the returned IdP
  // accounts. Return data for all the IdP accounts.
  std::vector<blink::mojom::IdentityUserInfoPtr> user_info;
  std::vector<blink::mojom::IdentityUserInfoPtr> not_returning_accounts;
  for (const auto& account : accounts) {
    if (IsReturningAccount(*account)) {
      user_info.push_back(blink::mojom::IdentityUserInfo::New(
          account->email, account->given_name, account->name,
          account->picture.spec()));
    } else {
      not_returning_accounts.push_back(blink::mojom::IdentityUserInfo::New(
          account->email, account->given_name, account->name,
          account->picture.spec()));
    }
  }
  // Non-returning accounts are appended after returning ones
  user_info.insert(user_info.end(), /*...*/);
```

The code explicitly returns data for all accounts -- the user may have consented to share Account A with this RP, but the RP also receives the email/name/picture of Accounts B, C, D.

## Attack Scenario
1. User has consented to use Account A (alice@example.com) with website.com via FedCM.
2. Website.com calls `getUserInfo()` for the same IdP.
3. The IdP returns accounts A (alice@example.com), B (bob@example.com), and C (carol@example.com).
4. The browser verifies that Account A is a returning account (has sharing permission).
5. The browser returns user info for ALL three accounts to website.com.
6. Website.com learns that bob@example.com and carol@example.com are accounts at this IdP, even though the user never consented to share those accounts.

## Impact
- Information disclosure: personal information (email, name, picture) of non-consented accounts is leaked.
- The number and identities of a user's accounts at an IdP are revealed to the RP.
- This could be used for targeted advertising, social engineering, or account enumeration.
- The issue exists by design (comment says "Return data for all the IdP accounts") but violates the principle of minimal disclosure.

## VRP Value
**Medium** -- This is a privacy issue that does not require a compromised renderer. Any website that has previously been granted FedCM access for one account can enumerate all accounts at the IdP. The impact depends on how many accounts the user has and how sensitive the account information is.
