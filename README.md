# PHPSEC 2.0

PHPSEC is a dependency-free, defensive static analyzer for PHP 8.2+. It reads source code and reports likely security defects; it does not execute targets or exploit applications.

## Usage

```bash
php phpsec.php scan ./app
php phpsec.php scan ./app --severity=HIGH --confidence=MEDIUM
php phpsec.php scan ./app --exclude=cache,generated --json
php phpsec.php scan ./app --html=report.html --sarif=results.sarif
php phpsec.php findings --severity=HIGH
php phpsec.php flow PHPSEC-001
php phpsec.php stats
```

Global options are `--quiet`, `--no-color`, and `--help`. Scan exits with `0` when clean, `2` when findings exist, and `1` on an error. The latest scan is cached in the system temporary directory for `findings`, `flow`, and `stats`.

Run the fixture suite with:

```bash
php tests/run.php
```

## Detectors

- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Path traversal and file inclusion
- Server-side request forgery (SSRF)
- Unsafe file upload
- Dangerous PHP functions
- Hardcoded secrets
- Weak security patterns

Reports are available as console output, version 2.0 JSON, standalone HTML, and SARIF 2.1.0.

## Architecture

```text
phpsec.php
src/
  CLI/          command parsing and cached scan commands
  Engine/       detector configuration and orchestration
  Scanner/      project/file traversal and scan results
  Parser/ AST/  token-based PHP model
  Taint/ Graph/ source-to-sink propagation
  Detectors/    vulnerability-specific rules
  Findings/     normalized findings and filtering
  Reporter/     console, JSON, HTML, and SARIF output
templates/      standalone report template
tests/Fixtures/ vulnerable and safe samples
```

`AnalysisEngine` is the public scan entry point. Configuration may be supplied through `phpsec.php.json`; supported keys include `exclude`, `severity.min`, `confidence.min`, `rules`, and `scan_root`.

## Limitations

PHPSEC uses token-based, mostly intra-file analysis. It does not fully model branches, loops, dynamic dispatch, framework routing, runtime types, or cross-file/cross-function data flow. Dynamic PHP features and context-dependent sanitization can produce false positives or false negatives. Findings require human review and do not replace dependency scanning, runtime testing, or a professional security assessment.

## Web UI

With XAMPP (or any PHP web server) serving this folder:

1. Open `http://localhost/phpsec/`
2. Browse to a folder or `.php` file under the allowlisted scan root (default: parent of this project, e.g. `C:\xampp\htdocs`)
3. Click **Scan** — results use the same V2 engine as the CLI
4. Filter, expand flows, or **Download .txt**

Override the browse/scan root with environment variable `PHPSEC_SCAN_ROOT`.

## Configuration

Optional `phpsec.php.json` in the project being scanned:

```json
{
  "exclude": ["vendor", "storage", "cache"],
  "severity": { "min": "LOW" },
  "confidence": { "min": "LOW" },
  "rules": {
    "sql_injection": true,
    "xss": true,
    "command_injection": true,
    "ssrf": true
  }
}
```

