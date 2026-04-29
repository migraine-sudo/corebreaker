chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  console.log('[DNR] Rule matched:', JSON.stringify(info));
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[DNR PoC] Extension installed.');
  console.log('[DNR PoC] Test by loading a page that includes <script src="https://testserver.example/redirect-target.js"></script>');
  console.log('[DNR PoC] If the script loads and executes, the data: URL redirect succeeded.');
  console.log('[DNR PoC] The rule should redirect the script request to a data: URL containing JavaScript.');
});
