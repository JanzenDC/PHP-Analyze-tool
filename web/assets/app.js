(() => {
  const api = "web/api.php";

  const els = {
    root: document.getElementById("scan-root"),
    rootPath: document.getElementById("root-path"),
    rootForm: document.getElementById("root-form"),
    ceiling: document.getElementById("path-ceiling"),
    path: document.getElementById("target-path"),
    form: document.getElementById("path-form"),
    scanBtn: document.getElementById("scan-btn"),
    upBtn: document.getElementById("up-btn"),
    crumbs: document.getElementById("crumbs"),
    entries: document.getElementById("entries"),
    status: document.getElementById("status"),
    resultsPanel: document.getElementById("results-panel"),
    resultsHead: document.getElementById("results-head"),
    placeholder: document.getElementById("placeholder"),
    resultsSub: document.getElementById("results-sub"),
    sevPills: document.getElementById("sev-pills"),
    downloadBtn: document.getElementById("download-btn"),
    stats: document.getElementById("stats"),
    toolbar: document.getElementById("toolbar"),
    filterQ: document.getElementById("filter-q"),
    groupByFile: document.getElementById("group-by-file"),
    shownCount: document.getElementById("shown-count"),
    findings: document.getElementById("findings"),
    emptyClean: document.getElementById("empty-clean"),
    emptyFilter: document.getElementById("empty-filter"),
    scanLoading: document.getElementById("scan-loading"),
  };

  let currentDir = "";
  let parentDir = null;
  let selectedPath = "";
  let lastScan = null;

  function setStatus(msg, isError = false) {
    els.status.textContent = msg || "";
    els.status.classList.toggle("error", Boolean(isError));
  }

  async function apiGet(action, params = {}) {
    const url = new URL(api, window.location.href);
    url.searchParams.set("action", action);
    Object.entries(params).forEach(([k, v]) => {
      if (v != null && v !== "") url.searchParams.set(k, v);
    });
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  async function apiPost(action, body) {
    const url = new URL(api, window.location.href);
    url.searchParams.set("action", action);
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  async function apiScan(path) {
    return apiPost("scan", { path });
  }

  function applyRootInfo(info) {
    if (info.root) {
      els.root.textContent = info.root;
      els.rootPath.value = info.root;
    }
    if (info.ceiling) els.ceiling.textContent = info.ceiling;
  }

  function selectPath(path, { syncInput = true } = {}) {
    selectedPath = path;
    if (syncInput) els.path.value = path;
    [...els.entries.querySelectorAll("li")].forEach((li) => {
      li.classList.toggle("selected", li.dataset.path === path);
    });
  }

  function renderBrowser(data) {
    currentDir = data.path;
    parentDir = data.parent;
    els.crumbs.textContent = data.path;
    els.upBtn.disabled = !parentDir;

    els.entries.innerHTML = "";
    if (!data.entries.length) {
      const empty = document.createElement("li");
      empty.style.cursor = "default";
      empty.innerHTML = `<span></span><span class="name" style="color:var(--muted)">Empty folder</span><span></span>`;
      els.entries.appendChild(empty);
      return;
    }

    data.entries.forEach((entry) => {
      const li = document.createElement("li");
      li.dataset.path = entry.path;
      li.dataset.type = entry.type;
      li.tabIndex = 0;
      li.innerHTML = `
        <span class="icon ${entry.type}" aria-hidden="true">${entry.type === "dir" ? "▸" : "·"}</span>
        <span class="name">${escapeHtml(entry.name)}</span>
        <span class="badge">${entry.type === "dir" ? "dir" : "php"}</span>
      `;
      li.addEventListener("click", () => {
        if (entry.type === "dir") {
          selectPath(entry.path);
          browse(entry.path);
        } else {
          selectPath(entry.path);
        }
      });
      li.addEventListener("dblclick", () => {
        if (entry.type === "dir") browse(entry.path);
        else runScan(entry.path);
      });
      li.addEventListener("keydown", (e) => {
        if (e.key === "Enter") li.click();
      });
      els.entries.appendChild(li);
    });

    if (selectedPath) {
      selectPath(selectedPath, { syncInput: false });
    } else {
      selectPath(data.path);
    }
  }

  async function browse(path) {
    setStatus("Listing…");
    try {
      const data = await apiGet("browse", { path });
      renderBrowser(data);
      selectPath(data.path);
      setStatus("");
    } catch (err) {
      setStatus(err.message, true);
    }
  }

  function countSeverity(findings) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((f) => {
      const s = String(f.severity || "").toUpperCase();
      if (counts[s] != null) counts[s] += 1;
    });
    return counts;
  }

  function normalizeSlashes(p) {
    return String(p || "").replace(/\\/g, "/");
  }

  function relPath(file, target) {
    const f = normalizeSlashes(file);
    const t = normalizeSlashes(target);
    if (!t) return f;
    const prefix = t.replace(/\/+$/, "");
    const lower = f.toLowerCase();
    const prefixLower = prefix.toLowerCase();
    if (lower === prefixLower) return ".";
    if (lower.startsWith(prefixLower + "/")) return f.slice(prefix.length + 1);
    const parts = f.split("/");
    return parts.length > 3 ? parts.slice(-3).join("/") : f;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function matchesFilter(f, q, target) {
    if (!q) return true;
    const hay = [
      f.id,
      f.type,
      f.severity,
      f.confidence,
      f.file,
      relPath(f.file, target),
      String(f.line),
      f.source,
      f.sink,
      ...(f.flow || []),
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  }

  function filteredFindings() {
    if (!lastScan) return [];
    const q = (els.filterQ.value || "").trim().toLowerCase();
    return (lastScan.findings || []).filter((f) => matchesFilter(f, q, lastScan.target));
  }

  function buildTextReport(findings) {
    const data = lastScan;
    const counts = countSeverity(findings);
    const s = data.stats || {};
    const lines = [];
    const bar = "=".repeat(64);
    const thin = "-".repeat(64);

    lines.push("PHPSEC — Security Scan Report");
    lines.push(bar);
    lines.push(`Target:      ${data.target}`);
    lines.push(`Generated:   ${new Date().toISOString()}`);
    lines.push(`Files:       ${s.files ?? "—"}`);
    lines.push(`PHP files:   ${s.phpFiles ?? "—"}`);
    lines.push(`Statements:  ${s.statements ?? "—"}`);
    lines.push(`Sink calls:  ${s.sinkCalls ?? "—"}`);
    lines.push("");
    lines.push(
      `Findings:    ${findings.length}  (CRITICAL ${counts.CRITICAL}, HIGH ${counts.HIGH}, MEDIUM ${counts.MEDIUM}, LOW ${counts.LOW})`
    );
    if ((els.filterQ.value || "").trim()) {
      lines.push(`Filter:      ${els.filterQ.value.trim()}`);
      lines.push(`(of ${(data.findings || []).length} total in scan)`);
    }
    lines.push(bar);
    lines.push("");

    if (!findings.length) {
      lines.push("No findings.");
      lines.push("");
      return lines.join("\r\n");
    }

    findings.forEach((f, i) => {
      const hops = [...(f.flow || []), f.sink].filter(Boolean);
      lines.push(`[${i + 1}] ${f.severity || "?"}  ${f.type || "Finding"}  (${f.id || "—"})`);
      lines.push(`    Confidence: ${f.confidence || "—"}`);
      lines.push(`    File:       ${relPath(f.file, data.target)}:${f.line}`);
      lines.push(`    Full path:  ${f.file}:${f.line}`);
      lines.push(`    Source:     ${f.source || "unknown"}`);
      lines.push(`    Sink:       ${f.sink || "—"}`);
      lines.push(`    Flow:       ${hops.join(" -> ")}`);
      if (f.reason || f.description) lines.push(`    Why:        ${f.reason || f.description}`);
      if (f.impact) lines.push(`    Impact:     ${f.impact}`);
      if (f.recommendation) lines.push(`    Fix:        ${f.recommendation}`);
      lines.push(thin);
      lines.push("");
    });

    return lines.join("\r\n");
  }

  function downloadText() {
    if (!lastScan) {
      setStatus("Run a scan first.", true);
      return;
    }
    const findings = filteredFindings();
    const text = buildTextReport(findings);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const base = normalizeSlashes(lastScan.target).split("/").filter(Boolean).pop() || "scan";
    const name = `phpsec-${base}-${stamp}.txt`;

    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus(`Downloaded ${name} (${findings.length} finding${findings.length === 1 ? "" : "s"}).`);
  }

  function renderResults(data) {
    lastScan = data;
    els.placeholder.hidden = true;
    els.resultsHead.hidden = false;
    els.stats.hidden = false;
    els.resultsSub.textContent = data.target;

    const counts = countSeverity(data.findings || []);
    els.sevPills.innerHTML = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
      .map((k) => `<span class="pill ${k.toLowerCase()}">${k} ${counts[k]}</span>`)
      .join("");

    const s = data.stats || {};
    els.stats.innerHTML = [
      ["Files", s.files ?? s.phpFiles],
      ["Statements", s.statements],
      ["Sources", s.sources],
      ["Sinks", s.sinks ?? s.sinkCalls],
      ["Functions", s.functions],
    ]
      .filter(([, value]) => value != null)
      .map(([label, value]) => `<span class="stat">${label}<strong>${value ?? "—"}</strong></span>`)
      .join("");

    const findings = data.findings || [];
    els.emptyClean.hidden = findings.length > 0;
    els.toolbar.hidden = findings.length === 0;
    els.downloadBtn.hidden = false;
    els.filterQ.value = "";
    paintFindingsList();
  }

  function paintFindingsList() {
    if (!lastScan) return;

    const target = lastScan.target;
    const group = els.groupByFile.checked;
    const all = lastScan.findings || [];
    const findings = filteredFindings();

    els.findings.innerHTML = "";
    els.emptyFilter.hidden = !(all.length > 0 && findings.length === 0);
    els.shownCount.textContent = all.length
      ? `Showing ${findings.length} of ${all.length}`
      : "";

    if (!findings.length) return;

    if (group) {
      const groups = new Map();
      findings.forEach((f) => {
        const key = f.file || "(unknown)";
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(f);
      });

      for (const [file, items] of groups) {
        const section = document.createElement("section");
        section.className = "file-group";

        const head = document.createElement("div");
        head.className = "file-group-head";

        const name = document.createElement("span");
        name.className = "file-group-name";
        name.title = file;
        name.textContent = relPath(file, target);

        const count = document.createElement("span");
        count.className = "file-group-count";
        count.textContent = String(items.length);

        head.appendChild(name);
        head.appendChild(count);

        const rows = document.createElement("div");
        rows.className = "finding-rows";
        items.forEach((f) => rows.appendChild(buildFindingRow(f, target, { hideFile: true })));

        section.appendChild(head);
        section.appendChild(rows);
        els.findings.appendChild(section);
      }
    } else {
      const table = document.createElement("div");
      table.className = "finding-table";
      findings.forEach((f) => table.appendChild(buildFindingRow(f, target, { hideFile: false })));
      els.findings.appendChild(table);
    }
  }

  function buildFindingRow(f, target, { hideFile }) {
    const sev = String(f.severity || "LOW").toUpperCase();
    const detailsId = `detail-${escapeHtml(f.id || Math.random().toString(36).slice(2))}`;
    const short = hideFile
      ? `line ${f.line}`
      : `${relPath(f.file, target)}:${f.line}`;
    const hops = [...(f.flow || []), f.sink].filter(Boolean);

    const wrap = document.createElement("div");
    wrap.className = "finding-item";

    wrap.innerHTML = `
      <button type="button" class="finding-row" aria-expanded="false" aria-controls="${detailsId}">
        <span class="sev ${sev.toLowerCase()}">${escapeHtml(sev)}</span>
        <span class="loc" title="${escapeHtml(f.file || "")}:${f.line}">
          <span class="loc-file">${escapeHtml(short)}</span>
        </span>
        <span class="trail">
          <code class="src">${escapeHtml(f.source || "unknown")}</code>
          <span class="arrow" aria-hidden="true">→</span>
          <code class="snk">${escapeHtml(f.sink || "—")}</code>
        </span>
        <span class="idcell">${escapeHtml(f.id || "—")}</span>
        <span class="chev" aria-hidden="true">▾</span>
      </button>
      <div class="finding-detail" id="${detailsId}" hidden>
        <div class="detail-grid">
          <div>
            <h3>File</h3>
            <code class="fullpath">${escapeHtml(f.file || "—")}:${f.line}</code>
          </div>
          <div>
            <h3>Confidence</h3>
            <code>${escapeHtml(f.confidence || "—")}</code>
          </div>
        </div>
        <div class="detail-flow">
          <h3>Data flow</h3>
          <ol class="flow-inline">${hops
            .map((h, i) => `<li><code>${escapeHtml(h)}</code>${i < hops.length - 1 ? '<span class="sep">→</span>' : ""}</li>`)
            .join("")}</ol>
        </div>
        <p class="why">${escapeHtml(f.reason || f.description || "")}</p>
        <p class="fix">${f.recommendation ? escapeHtml("Fix: " + f.recommendation) : ""}</p>
      </div>
    `;

    const btn = wrap.querySelector(".finding-row");
    const detail = wrap.querySelector(".finding-detail");
    btn.addEventListener("click", () => {
      const open = detail.hidden;
      wrap.parentElement?.querySelectorAll(".finding-detail").forEach((d) => {
        d.hidden = true;
      });
      wrap.parentElement?.querySelectorAll(".finding-row").forEach((b) => {
        b.setAttribute("aria-expanded", "false");
        b.classList.remove("open");
      });
      if (open) {
        detail.hidden = false;
        btn.setAttribute("aria-expanded", "true");
        btn.classList.add("open");
      }
    });

    return wrap;
  }

  async function runScan(path) {
    const target = (path || els.path.value || "").trim();
    if (!target) {
      setStatus("Choose a folder or PHP file first.", true);
      return;
    }

    els.scanBtn.disabled = true;
    els.scanLoading.hidden = false;
    setStatus(`Scanning ${target}…`);
    try {
      const data = await apiScan(target);
      renderResults(data);
      const n = (data.findings || []).length;
      setStatus(n ? `Done — ${n} finding${n === 1 ? "" : "s"}.` : "Done — clean.");
    } catch (err) {
      setStatus(err.message, true);
    } finally {
      els.scanBtn.disabled = false;
      els.scanLoading.hidden = true;
    }
  }

  els.rootForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const next = (els.rootPath.value || "").trim();
    if (!next) {
      setStatus("Enter a folder to use as scan root.", true);
      return;
    }
    setStatus("Updating scan root…");
    try {
      const info = await apiPost("set_root", { path: next });
      applyRootInfo(info);
      await browse(info.root);
      setStatus(`Scan root set to ${info.root}`);
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  els.form.addEventListener("submit", (e) => {
    e.preventDefault();
    runScan(els.path.value);
  });

  els.upBtn.addEventListener("click", () => {
    if (parentDir) browse(parentDir);
  });

  els.path.addEventListener("change", () => {
    const v = els.path.value.trim();
    if (v) selectPath(v, { syncInput: false });
  });

  els.downloadBtn.addEventListener("click", downloadText);

  let filterTimer = null;
  els.filterQ.addEventListener("input", () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(paintFindingsList, 120);
  });
  els.groupByFile.addEventListener("change", paintFindingsList);

  (async () => {
    try {
      const rootInfo = await apiGet("root");
      applyRootInfo(rootInfo);
      await browse(rootInfo.root || rootInfo.default);
    } catch (err) {
      setStatus(err.message, true);
    }
  })();
})();
