<?php
declare(strict_types=1);

/**
 * Path helpers for the PHPSEC web UI (allowlisted browse/scan).
 */

function phpsec_scan_root(): string
{
    $env = getenv('PHPSEC_SCAN_ROOT');
    if (is_string($env) && $env !== '' && is_dir($env)) {
        $real = realpath($env);
        return $real !== false ? $real : $env;
    }

    $projectRoot = realpath(dirname(__DIR__, 2));
    if ($projectRoot !== false) {
        $htdocs = realpath(dirname($projectRoot));
        if ($htdocs !== false && is_dir($htdocs)) {
            return $htdocs;
        }
        return $projectRoot;
    }

    return dirname(__DIR__, 2);
}

function phpsec_resolve_under_root(string $path, ?string $root = null): ?string
{
    $root = $root ?? phpsec_scan_root();
    $rootReal = realpath($root);
    if ($rootReal === false) {
        return null;
    }

    $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, trim($path));

    if (preg_match('#^[a-zA-Z]:\\\\#', $path) || str_starts_with($path, DIRECTORY_SEPARATOR)) {
        $candidate = $path;
    } else {
        $candidate = $rootReal . DIRECTORY_SEPARATOR . ltrim($path, DIRECTORY_SEPARATOR);
    }

    $parts = [];
    foreach (explode(DIRECTORY_SEPARATOR, $candidate) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            array_pop($parts);
            continue;
        }
        $parts[] = $part;
    }

    if (preg_match('#^[a-zA-Z]:$#', $parts[0] ?? '')) {
        $normalized = $parts[0] . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_slice($parts, 1));
    } else {
        $normalized = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    }

    $exists = realpath($normalized);
    $check = $exists !== false ? $exists : $normalized;

    $rootPrefix = rtrim($rootReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    $checkNorm = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $check), DIRECTORY_SEPARATOR);
    $rootNorm = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $rootReal), DIRECTORY_SEPARATOR);

    if ($checkNorm !== $rootNorm && !str_starts_with($checkNorm . DIRECTORY_SEPARATOR, $rootPrefix)) {
        return null;
    }

    return $exists !== false ? $exists : $normalized;
}

/**
 * @return array{path: string, parent: ?string, root: string, entries: list<array{name: string, path: string, type: string}>}|array{error: string}
 */
function phpsec_list_directory(string $path, bool $includePhpFiles = true): array
{
    $resolved = phpsec_resolve_under_root($path);
    if ($resolved === null || !is_dir($resolved)) {
        return ['error' => 'Directory not found or outside the allowed scan root.'];
    }

    $root = phpsec_scan_root();
    $parent = null;
    if ($resolved !== $root) {
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
        'entries' => $entries,
    ];
}
