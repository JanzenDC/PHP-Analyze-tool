<?php
declare(strict_types=1);

/**
 * Path helpers for the PHPSEC web UI (allowlisted browse/scan).
 */

function phpsec_project_dir(): string
{
    $dir = realpath(dirname(__DIR__, 2));
    return $dir !== false ? $dir : dirname(__DIR__, 2);
}

/** Hard ceiling so the UI cannot wander the whole OS unless explicitly widened. */
function phpsec_path_ceiling(): string
{
    $env = getenv('PHPSEC_PATH_CEILING');
    if (is_string($env) && $env !== '' && is_dir($env)) {
        $real = realpath($env);
        return $real !== false ? $real : $env;
    }

    // Default: XAMPP (or parent of htdocs), else the drive / project parent.
    $htdocs = phpsec_default_scan_root();
    $xampp = realpath(dirname($htdocs));
    if ($xampp !== false && is_dir($xampp)) {
        return $xampp;
    }
    return $htdocs;
}

function phpsec_default_scan_root(): string
{
    $env = getenv('PHPSEC_SCAN_ROOT');
    if (is_string($env) && $env !== '' && is_dir($env)) {
        $real = realpath($env);
        return $real !== false ? $real : $env;
    }

    $projectRoot = phpsec_project_dir();
    $htdocs = realpath(dirname($projectRoot));
    if ($htdocs !== false && is_dir($htdocs)) {
        return $htdocs;
    }
    return $projectRoot;
}

function phpsec_ensure_session(): void
{
    if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
        return;
    }
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function phpsec_scan_root(): string
{
    phpsec_ensure_session();
    $sessionRoot = $_SESSION['phpsec_scan_root'] ?? null;
    if (is_string($sessionRoot) && $sessionRoot !== '') {
        $real = realpath($sessionRoot);
        if ($real !== false && is_dir($real) && phpsec_is_under($real, phpsec_path_ceiling())) {
            return $real;
        }
    }
    return phpsec_default_scan_root();
}

function phpsec_set_scan_root(string $path): array
{
    $normalized = phpsec_normalize_path($path);
    if ($normalized === null) {
        return ['error' => 'Invalid path.'];
    }
    $real = realpath($normalized);
    if ($real === false || !is_dir($real)) {
        return ['error' => 'Directory not found.'];
    }
    if (!phpsec_is_under($real, phpsec_path_ceiling())) {
        return [
            'error' => 'Scan root must stay under ' . phpsec_path_ceiling() . '. Set PHPSEC_PATH_CEILING to widen this.',
        ];
    }

    phpsec_ensure_session();
    $_SESSION['phpsec_scan_root'] = $real;
    return [
        'root' => $real,
        'ceiling' => phpsec_path_ceiling(),
        'default' => phpsec_default_scan_root(),
    ];
}

function phpsec_is_windows_absolute(string $path): bool
{
    return (bool) preg_match('#^[a-zA-Z]:[\\\\/]#', $path);
}

function phpsec_normalize_path(string $path): ?string
{
    $path = trim($path);
    if ($path === '') {
        return null;
    }
    $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);

    if (phpsec_is_windows_absolute($path) || str_starts_with($path, DIRECTORY_SEPARATOR)) {
        $candidate = $path;
    } else {
        $candidate = phpsec_scan_root() . DIRECTORY_SEPARATOR . ltrim($path, DIRECTORY_SEPARATOR);
    }

    $parts = [];
    foreach (explode(DIRECTORY_SEPARATOR, $candidate) as $i => $part) {
        if ($part === '' || $part === '.') {
            // Keep Windows drive empty-skip; keep leading empty for UNC/unix later if needed.
            if ($i === 0 && phpsec_is_windows_absolute($candidate)) {
                continue;
            }
            continue;
        }
        if ($part === '..') {
            array_pop($parts);
            continue;
        }
        $parts[] = $part;
    }

    if ($parts === []) {
        return null;
    }

    if (preg_match('#^[a-zA-Z]:$#', $parts[0])) {
        return $parts[0] . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_slice($parts, 1));
    }

    return DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
}

function phpsec_is_under(string $path, string $root): bool
{
    $pathNorm = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path), DIRECTORY_SEPARATOR);
    $rootNorm = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $root), DIRECTORY_SEPARATOR);
    if (strcasecmp($pathNorm, $rootNorm) === 0) {
        return true;
    }
    $prefix = $rootNorm . DIRECTORY_SEPARATOR;
    return str_starts_with(strtolower($pathNorm . DIRECTORY_SEPARATOR), strtolower($prefix));
}

function phpsec_resolve_under_root(string $path, ?string $root = null): ?string
{
    $root = $root ?? phpsec_scan_root();
    $rootReal = realpath($root);
    if ($rootReal === false) {
        return null;
    }

    $normalized = phpsec_normalize_path($path);
    if ($normalized === null) {
        return null;
    }

    $exists = realpath($normalized);
    $check = $exists !== false ? $exists : $normalized;

    if (!phpsec_is_under($check, $rootReal)) {
        return null;
    }

    return $exists !== false ? $exists : $normalized;
}

/**
 * @return array{path: string, parent: ?string, root: string, ceiling: string, entries: list<array{name: string, path: string, type: string}>}|array{error: string}
 */
function phpsec_list_directory(string $path, bool $includePhpFiles = true): array
{
    $resolved = phpsec_resolve_under_root($path);
    if ($resolved === null || !is_dir($resolved)) {
        return ['error' => 'Directory not found or outside the allowed scan root.'];
    }

    $root = phpsec_scan_root();
    $parent = null;
    if (strcasecmp($resolved, $root) !== 0) {
        $parentDir = dirname($resolved);
        $parentResolved = phpsec_resolve_under_root($parentDir);
        if ($parentResolved !== null) {
            $parent = $parentResolved;
        }
    }

    $entries = [];
    $items = @scandir($resolved);
    if ($items === false) {
        return ['error' => 'Unable to read directory.'];
    }

    foreach ($items as $name) {
        if ($name === '.' || $name === '..') {
            continue;
        }
        if (in_array($name, ['vendor', 'node_modules', '.git'], true)) {
            continue;
        }

        $full = $resolved . DIRECTORY_SEPARATOR . $name;
        if (is_dir($full)) {
            $entries[] = ['name' => $name, 'path' => $full, 'type' => 'dir'];
        } elseif ($includePhpFiles && is_file($full) && str_ends_with(strtolower($name), '.php')) {
            $entries[] = ['name' => $name, 'path' => $full, 'type' => 'file'];
        }
    }

    usort($entries, static function (array $a, array $b): int {
        if ($a['type'] !== $b['type']) {
            return $a['type'] === 'dir' ? -1 : 1;
        }
        return strcasecmp($a['name'], $b['name']);
    });

    return [
        'path' => $resolved,
        'parent' => $parent,
        'root' => $root,
        'ceiling' => phpsec_path_ceiling(),
        'entries' => $entries,
    ];
}
