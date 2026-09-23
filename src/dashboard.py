DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>watchTower</title>
<style>
  body { font-family: system-ui, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:2rem; }
  h1 { font-size:1.4rem; margin-bottom:0.25rem; }
  .sub { color:#8b949e; font-size:0.85rem; margin-bottom:1.5rem; }
  .key-row { display:flex; gap:0.5rem; margin-bottom:1.5rem; max-width:420px; }
  input[type=password] { background:#161b22; border:1px solid #30363d; color:#c9d1d9; padding:0.4rem 0.6rem; border-radius:6px; flex:1; font-family:inherit; }
  button { background:#238636; border:none; color:white; padding:0.4rem 0.9rem; border-radius:6px; cursor:pointer; }
  button:hover { background:#2ea043; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:0.5rem 0.75rem; border-bottom:1px solid #21262d; font-size:0.9rem; }
  th { color:#8b949e; font-weight:600; text-transform:uppercase; font-size:0.75rem; }
  tr:hover { background:#161b22; }
  .rule { font-weight:600; }
  .empty, .error { color:#8b949e; padding:2rem 0; text-align:center; }
  .error { color:#f85149; }
  #status { font-size:0.8rem; color:#8b949e; margin-left:0.5rem; }
</style>
</head>
<body>
  <h1>watchTower</h1>
  <div class="sub">alerts, refreshed every 15s<span id="status"></span></div>

  <div class="key-row">
    <input id="apiKey" type="password" placeholder="X-API-Key">
    <button onclick="saveKey()">Connect</button>
  </div>

  <div id="content"><div class="empty">enter your API key to load alerts</div></div>

<script>
const KEY_STORAGE = "watchtower_api_key";

function saveKey() {
  const key = document.getElementById("apiKey").value.trim();
  if (!key) return;
  try { localStorage.setItem(KEY_STORAGE, key); } catch (e) {}
  loadAlerts();
}

function fmtEntity(v) {
  return v === null ? "—" : v;
}

async function loadAlerts() {
  let key;
  try { key = localStorage.getItem(KEY_STORAGE); } catch (e) { key = null; }
  if (!key) return;

  const status = document.getElementById("status");
  const content = document.getElementById("content");

  try {
    const res = await fetch("/alerts?limit=100", { headers: { "X-API-Key": key } });
    if (res.status === 401) {
      content.innerHTML = '<div class="error">invalid API key</div>';
      status.textContent = "";
      return;
    }
    if (!res.ok) {
      content.innerHTML = '<div class="error">request failed (' + res.status + ')</div>';
      return;
    }
    const alerts = await res.json();
    status.textContent = " · updated " + new Date().toLocaleTimeString();

    if (alerts.length === 0) {
      content.innerHTML = '<div class="empty">no alerts yet</div>';
      return;
    }

    const rows = alerts.map(function(a) {
      return "<tr>" +
        "<td class=\\"rule\\">" + a.rule_name + "</td>" +
        "<td>" + fmtEntity(a.matched_entity) + "</td>" +
        "<td>" + a.count + "</td>" +
        "<td>" + a.window_seconds + "s</td>" +
        "<td>" + a.triggered_at + "</td>" +
        "</tr>";
    }).join("");

    content.innerHTML =
      "<table><thead><tr><th>Rule</th><th>Entity</th><th>Count</th><th>Window</th><th>Triggered</th></tr></thead>" +
      "<tbody>" + rows + "</tbody></table>";
  } catch (e) {
    content.innerHTML = '<div class="error">could not reach the server</div>';
  }
}

(function init() {
  let saved;
  try { saved = localStorage.getItem(KEY_STORAGE); } catch (e) { saved = null; }
  if (saved) {
    document.getElementById("apiKey").value = saved;
    loadAlerts();
  }
  setInterval(loadAlerts, 15000);
})();
</script>
</body>
</html>
"""
