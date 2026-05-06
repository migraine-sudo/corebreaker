// Victim extension: simulates a password manager storing credentials
// On install, populate storage with fake credentials

browser.runtime.onInstalled.addListener(() => {
  browser.storage.local.set({
    vault: {
      "bank.example.com": {
        username: "john.doe@email.com",
        password: "B@nk$ecure2024!",
        notes: "Primary checking account"
      },
      "mail.google.com": {
        username: "john.doe@gmail.com",
        password: "Gm@ilP@ss99#",
        notes: "Personal email"
      },
      "github.com": {
        username: "johndoe-dev",
        password: "gh_pat_xK9mN2pQ7rS4tU6v",
        notes: "Developer account - has org access"
      },
      "crypto-wallet.io": {
        username: "john_crypto",
        password: "W@llet_M@ster_Key_2024",
        seed_phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident"
      }
    },
    settings: {
      autoFill: true,
      lockTimeout: 300,
      masterPasswordHash: "sha256:a1b2c3d4e5f6..."
    }
  });

  console.log("[Secure Vault] Credentials stored in extension storage.");
});

// Listen for messages from popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getVault") {
    browser.storage.local.get("vault").then(data => {
      sendResponse(data.vault);
    });
    return true;
  }
});
