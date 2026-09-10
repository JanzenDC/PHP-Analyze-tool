# PHPSEC — Native PHP Security Analyzer (V1)

A standalone, dependency-free static analysis CLI for plain PHP applications.
It traces user input from **source** (`$_GET`, `$_POST`, etc.) to **sink**
(SQL execution functions) and reports where untrusted data reaches a
dangerous call without passing through a recognized sanitizer or
parameterized query. It does not execute or exploit anything — it's a
read-only source-code scanner.

## Requirements

- PHP 8.1+ (uses `token_get_all()`, no extensions, no Composer)

## Usage

### CLI

```bash
php phpsec.php scan ./my-project
php phpsec.php scan ./my-project/api/users.php
php phpsec.php scan ./my-project --json
```

Exit codes: `0` = no findings, `2` = findings present, `1` = usage/path error.

### Web UI

With XAMPP (or any PHP web server) serving this folder:

1. Open `http://localhost/phpsec/`
2. Browse to the folder (or `.php` file) you want to analyze
3. Click **Scan**

The folder browser is limited to an allowlisted **scan root** (default: the parent of this project, e.g. `C:\xampp\htdocs`). Override with the environment variable `PHPSEC_SCAN_ROOT`.

## V1 scope (what's actually implemented)

- **One vulnerability class**: SQL Injection.
- **Sinks recognized**: `mysqli_query()`, `mysqli_multi_query()`,
  `->query()`, `->exec()` (the last two are a heuristic — see Limitations).
- **Sources recognized**: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`,
  `$_SERVER`, `$_FILES`, `$_ENV`.
- **Sanitizers recognized** (taint-clearing): `(int)`, `(float)`, `(bool)`
  casts, `intval`, `floatval`, `boolval`, `mysqli_real_escape_string`,
  `htmlspecialchars`, `htmlentities`, `addslashes`, `preg_quote`, `basename`.
- **Propagation**: direct assignment, string interpolation, and
  concatenation. This works because PHP's own tokenizer (`token_get_all`)
  emits interpolated/concatenated variables as standalone `T_VARIABLE`
  tokens — no custom string-parsing was needed to catch
  `"...WHERE id = $id"` style injection.

## Architecture

```
phpsec.php / index.php        CLI + web entrypoints
web/
├── api.php                   browse + scan JSON API
└── assets/                   UI CSS/JS
src/
├── lib.php                   shared scan/browse helpers
├── Parser/
│   └── TokenWalker.php       token_get_all() -> Statement[] (split on top-level ';')
├── Taint/
│   ├── TaintInfo.php         per-variable taint state + flow chain
│   └── TaintEngine.php       propagates taint across a flat statement list
└── Detectors/
    ├── Finding.php           structured finding record
    └── SQLInjection.php      matches sink calls, checks args against taint map
tests/
├── vulnerable.php            3 SQLi patterns (concat, interpolation, PDO)
└── safe.php                  same patterns, properly mitigated -> 0 findings
```

## Known V1 limitations (intentionally punted, not bugs)

These are the things a "real" static analyzer would need next, deliberately
deferred so the core engine could ship and be verified first:

1. **No control-flow modeling.** Every statement is treated as if it always
   executes, in file order. An `if ($safe) { $sql = ... }` branch that never
   actually reaches the sink at runtime is still analyzed as if it does.
   This can cause both false positives and false negatives around
   conditional sanitization.
2. **No cross-file/cross-function taint tracking.** If `$id` is tainted in
   `index.php` and passed into a function defined in `functions/db.php`,
   V1 does not follow it through the function boundary. Each file is
   analyzed independently.
3. **`->query()` / `->exec()` sink matching is a heuristic.** Without
   resolving the receiver's actual class, PHPSEC can't confirm it's really
   a `PDO` (or `mysqli`) object — it flags any `->query()`/`->exec()` call
   with a tainted argument, at `MEDIUM` confidence instead of `HIGH`. This
   deliberately favors false positives over silently missing real PDO
   sinks.
4. **`filter_var()` is not yet modeled as a sanitizer** even though it's
   listed as a common one, because whether it actually sanitizes depends
   on which `FILTER_*` constant is passed — that argument-value inspection
   isn't implemented in V1.
5. **No loops, no arrays/objects as taint carriers.** `$arr['id'] = $_GET['id']; foo($arr);`
   is not tracked — only scalar variable taint is modeled.
6. **One detector only.** XSS, command injection, path traversal, SSRF,
   file inclusion, and the other categories from the original design doc
   are not implemented yet — the architecture (Taint engine + pluggable
   Detectors) is built to add them without changes to the core engine.

## Suggested next steps (V2+)

- Add `Detectors/CommandInjection.php` and `Detectors/XSS.php` reusing the
  same `TaintEngine` — this validates that the engine is actually
  detector-agnostic before investing in harder problems.
- Basic branch awareness: treat `if`/`else` bodies as alternative taint
  states and merge (tainted if *either* branch leaves it tainted) rather
  than assuming linear execution.
- Resolve `->query`/`->exec` receiver type via simple local
  `new PDO(...)` / `new mysqli(...)` tracking to upgrade confidence to HIGH
  when the class is known.
