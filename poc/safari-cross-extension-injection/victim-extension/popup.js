// Display vault entries in popup
browser.storage.local.get("vault").then(data => {
  const entries = document.getElementById("entries");
  if (!data.vault) {
    entries.textContent = "Vault is empty.";
    return;
  }
  entries.innerHTML = "";
  for (const [site, cred] of Object.entries(data.vault)) {
    const div = document.createElement("div");
    div.className = "entry";
    div.innerHTML = `
      <div class="site">${site}</div>
      <div class="user">${cred.username}</div>
      <div class="pass">••••••••</div>
    `;
    entries.appendChild(div);
  }
});
