<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PHPSEC V2 — Scan target</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="web/assets/app.css">
</head>
<body>
  <div class="shell">
    <header class="top">
      <div class="brand">
        <span class="mark" aria-hidden="true"></span>
        <div>
          <h1>PHPSEC</h1>
          <p>Native PHP security analyzer · V2 data-flow engine</p>
        </div>
      </div>
      <div class="root-controls">
        <p class="root-hint">Scan root: <code id="scan-root">…</code></p>
        <form id="root-form" class="root-row" autocomplete="off">
          <label class="sr-only" for="root-path">Change scan root</label>
          <input id="root-path" type="text" spellcheck="false" placeholder="Set allowlisted root (e.g. C:\xampp\htdocs)">
          <button type="submit" class="btn ghost" id="root-btn">Set root</button>
        </form>
        <p class="root-ceiling">Ceiling: <code id="path-ceiling">…</code></p>
      </div>
    </header>

    <main class="workspace">
      <aside class="panel target" aria-labelledby="target-heading">
        <div class="panel-head">
          <h2 id="target-heading">Target folder</h2>
          <p>Browse and pick a folder or PHP file to scan.</p>
        </div>

        <form id="path-form" class="path-row" autocomplete="off">
          <label class="sr-only" for="target-path">Scan path</label>
          <input id="target-path" name="path" type="text" spellcheck="false" placeholder="Folder or .php file path">
          <button type="submit" class="btn primary" id="scan-btn">Scan</button>
        </form>

        <div class="browser" id="browser">
          <div class="browser-bar">
            <button type="button" class="btn ghost" id="up-btn" disabled>↑ Up</button>
            <code class="crumbs" id="crumbs">—</code>
          </div>
          <ul class="entries" id="entries" role="list"></ul>
          <p class="browser-note">Targets must stay under the scan root. Use <strong>Set root</strong> to point at <code>htdocs</code> (or another folder under the ceiling) first.</p>
        </div>

        <p class="status" id="status" role="status" aria-live="polite"></p>
        <div class="scan-loading" id="scan-loading" hidden>
          <div class="loader" aria-hidden="true"></div>
          <p class="scan-loading-label">Scanning…</p>
        </div>
      </aside>

      <section class="panel results" aria-labelledby="results-heading" id="results-panel">
        <div class="panel-head row" id="results-head" hidden>
          <div>
            <h2 id="results-heading">Results</h2>
            <p id="results-sub">—</p>
          </div>
          <div class="results-actions">
            <div class="sev-pills" id="sev-pills" aria-live="polite"></div>
            <button type="button" class="btn ghost" id="download-btn" hidden>Download .txt</button>
          </div>
        </div>

        <div class="stats" id="stats" hidden></div>

        <div class="toolbar" id="toolbar" hidden>
          <label class="sr-only" for="filter-q">Filter findings</label>
          <input id="filter-q" type="search" placeholder="Filter by file, source, sink, id…">
          <label class="group-toggle">
            <input type="checkbox" id="group-by-file" checked>
            Group by file
          </label>
          <span class="shown-count" id="shown-count"></span>
        </div>

        <div id="findings" class="findings"></div>
        <p class="empty" id="empty-clean" hidden>No SQL injection findings in this target.</p>
        <p class="empty muted" id="empty-filter" hidden>No findings match this filter.</p>

        <div class="panel placeholder" id="placeholder">
          <h2>Results appear here</h2>
          <p>Choose a project on the left and click <strong>Scan</strong>. Findings show on this side — filter, expand, or download as text.</p>
        </div>
      </section>
    </main>
  </div>

  <script src="web/assets/app.js"></script>
</body>
</html>
