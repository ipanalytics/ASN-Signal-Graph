const SIGNALS = ["vpn", "tor", "drop_list", "public_feed"];

let records = [];
let selectedSort = "signal_count";
let sortDirection = "desc";

const state = {
  search: "",
  signal: "all",
  level: "all",
  country: "all",
  minSources: 1,
  minSignals: 0,
};

const els = {
  summary: document.querySelector("#summaryStrip"),
  body: document.querySelector("#matrixBody"),
  resultCount: document.querySelector("#resultCount"),
  detail: document.querySelector("#detailPanel"),
  search: document.querySelector("#searchInput"),
  signal: document.querySelector("#signalSelect"),
  level: document.querySelector("#levelSelect"),
  country: document.querySelector("#countrySelect"),
  minSources: document.querySelector("#sourceInput"),
  minSignals: document.querySelector("#signalInput"),
  reset: document.querySelector("#resetButton"),
  tabs: document.querySelectorAll(".view-tabs button"),
  headers: document.querySelectorAll(".sort-header"),
};

fetch("../data/current/dashboard-data.json")
  .then((response) => response.json())
  .then((data) => {
    records = data.records || [];
    initialize();
  });

function initialize() {
  renderSummary();
  populateCountries();
  bindEvents();
  render();
}

function bindEvents() {
  els.search.addEventListener("input", (event) => {
    state.search = event.target.value.trim().toLowerCase();
    render();
  });
  els.signal.addEventListener("change", (event) => {
    state.signal = event.target.value;
    render();
  });
  els.level.addEventListener("change", (event) => {
    state.level = event.target.value;
    render();
  });
  els.country.addEventListener("change", (event) => {
    state.country = event.target.value;
    render();
  });
  els.minSources.addEventListener("input", (event) => {
    state.minSources = Number(event.target.value || 1);
    render();
  });
  els.minSignals.addEventListener("input", (event) => {
    state.minSignals = Number(event.target.value || 0);
    render();
  });
  els.summary.addEventListener("click", (event) => {
    const metric = event.target.closest("[data-signal]");
    if (!metric) return;
    state.signal = metric.dataset.signal;
    els.signal.value = state.signal;
    state.level = "all";
    els.level.value = "all";
    render();
  });
  els.reset.addEventListener("click", resetFilters);
  els.tabs.forEach((button) => {
    button.addEventListener("click", () => {
      els.tabs.forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      selectedSort = button.dataset.sort;
      sortDirection = "desc";
      updateSortHeaders();
      render();
    });
  });
  els.headers.forEach((button) => {
    button.addEventListener("click", () => {
      const column = button.dataset.column;
      if (selectedSort === column) {
        sortDirection = sortDirection === "desc" ? "asc" : "desc";
      } else {
        selectedSort = column;
        sortDirection = defaultDirection(column);
      }
      els.tabs.forEach((item) => item.classList.toggle("active", item.dataset.sort === selectedSort));
      updateSortHeaders();
      render();
    });
  });
  updateSortHeaders();
}

function renderSummary() {
  const totals = {
    asns: records.length,
    vpn: records.filter((record) => record.signals.vpn.count > 0).length,
    tor: records.filter((record) => record.signals.tor.count > 0).length,
    drop: records.filter((record) => record.signals.drop_list.count > 0).length,
    publicFeed: records.filter((record) => record.signals.public_feed.count > 0).length,
  };
  els.summary.innerHTML = `
    ${metric(totals.asns.toLocaleString(), "ASNs")}
    ${metric(totals.vpn.toLocaleString(), "VPN overlap", "vpn")}
    ${metric(totals.tor.toLocaleString(), "Tor overlap", "tor")}
    ${metric(totals.drop.toLocaleString(), "DROP listed", "drop_list")}
    ${metric(totals.publicFeed.toLocaleString(), "Public feed", "public_feed")}
  `;
}

function metric(value, label, signal = "") {
  const attribute = signal ? ` data-signal="${signal}"` : "";
  return `<div class="metric"${attribute}><strong>${value}</strong><span>${label}</span></div>`;
}

function populateCountries() {
  const countries = [...new Set(records.map((record) => record.country || "ZZ"))].sort();
  for (const country of countries) {
    const option = document.createElement("option");
    option.value = country;
    option.textContent = country;
    els.country.appendChild(option);
  }
}

function render() {
  const filtered = records.filter(matchesFilters).sort(sortRecords).slice(0, 500);
  els.resultCount.textContent = `${filtered.length.toLocaleString()} shown · ${activeFilterCount()} active filters`;
  els.body.innerHTML = filtered.map(rowHtml).join("");
  els.body.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", () => showDetail(Number(row.dataset.asn)));
  });
}

function matchesFilters(record) {
  if (state.search) {
    const haystack = `${record.asn} ${record.org}`.toLowerCase();
    if (!haystack.includes(state.search)) return false;
  }
  if (state.country !== "all" && record.country !== state.country) return false;
  if (record.source_count < state.minSources) return false;
  if (record.signal_count < state.minSignals) return false;
  if (state.signal !== "all") {
    const signal = record.signals[state.signal];
    if (!signal || signal.count <= 0) return false;
    if (state.level !== "all" && signal.level !== state.level) return false;
  } else if (state.level !== "all") {
    const hasLevel = SIGNALS.some((key) => record.signals[key]?.level === state.level);
    if (!hasLevel) return false;
  }
  return true;
}

function activeFilterCount() {
  let count = 0;
  if (state.search) count += 1;
  if (state.signal !== "all") count += 1;
  if (state.level !== "all") count += 1;
  if (state.country !== "all") count += 1;
  if (state.minSources > 1) count += 1;
  if (state.minSignals > 0) count += 1;
  return count;
}

function resetFilters() {
  state.search = "";
  state.signal = "all";
  state.level = "all";
  state.country = "all";
  state.minSources = 1;
  state.minSignals = 0;
  selectedSort = "signal_count";
  sortDirection = "desc";
  els.search.value = "";
  els.signal.value = "all";
  els.level.value = "all";
  els.country.value = "all";
  els.minSources.value = "1";
  els.minSignals.value = "0";
  els.tabs.forEach((button) => {
    button.classList.toggle("active", button.dataset.sort === selectedSort);
  });
  updateSortHeaders();
  render();
}

function sortRecords(a, b) {
  const direction = sortDirection === "asc" ? 1 : -1;
  return compareRecords(a, b, selectedSort) * direction;
}

function compareRecords(a, b, column) {
  if (SIGNALS.includes(column)) {
    return (a.signals[column]?.count || 0) - (b.signals[column]?.count || 0);
  }
  if (["asn", "signal_count", "source_count"].includes(column)) {
    return Number(a[column] || 0) - Number(b[column] || 0);
  }
  return String(a[column] || "").localeCompare(String(b[column] || ""), undefined, {
    numeric: true,
    sensitivity: "base",
  });
}

function defaultDirection(column) {
  return ["org", "country", "infrastructure_role"].includes(column) ? "asc" : "desc";
}

function updateSortHeaders() {
  els.headers.forEach((button) => {
    const active = button.dataset.column === selectedSort;
    button.classList.toggle("active", active);
    button.dataset.direction = active ? sortDirection : "";
  });
}

function rowHtml(record) {
  return `
    <tr data-asn="${record.asn}">
      <td>${record.asn}</td>
      <td class="org-cell" title="${escapeHtml(record.org)}">${escapeHtml(record.org || "unknown")}</td>
      <td>${record.country || "ZZ"}</td>
      ${SIGNALS.map((key) => signalCell(record.signals[key])).join("")}
      <td>${record.source_count}</td>
      <td>${escapeHtml(record.infrastructure_role)}</td>
    </tr>
  `;
}

function signalCell(signal) {
  return `<td><span class="pill level-${signal.level}">${signal.count.toLocaleString()}</span></td>`;
}

function showDetail(asn) {
  const record = records.find((item) => item.asn === asn);
  if (!record) return;
  els.detail.innerHTML = `
    <h2>${escapeHtml(record.org || "unknown")}</h2>
    <div class="asn">AS${record.asn} · ${record.country || "ZZ"}</div>
    <div class="detail-section">
      <div class="signal-row"><span>Total signals</span><strong>${record.signal_count.toLocaleString()}</strong></div>
      <div class="signal-row"><span>Sources</span><strong>${record.source_count}</strong></div>
      <div class="signal-row"><span>Confidence</span><strong>${record.confidence}</strong></div>
      <div class="signal-row"><span>Role</span><strong>${escapeHtml(record.infrastructure_role)}</strong></div>
    </div>
    <div class="detail-section">
      ${SIGNALS.map((key) => detailSignal(key, record.signals[key])).join("")}
    </div>
    <div class="detail-section labels">
      ${record.labels.map((label) => `<span class="label-chip">${escapeHtml(label)}</span>`).join("")}
    </div>
    <a class="api-link" href="../data/api/asn/${record.asn}.json">Open JSON</a>
  `;
}

function detailSignal(key, signal) {
  const label = key.replace("_", " ").toUpperCase();
  return `
    <div class="signal-row">
      <span>${label}</span>
      <span class="pill level-${signal.level}">${signal.count.toLocaleString()}</span>
    </div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
