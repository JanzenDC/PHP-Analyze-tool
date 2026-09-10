<?php

/**
 * Shared PHPSEC scan helpers used by the CLI and the web UI.
 */

require_once __DIR__ . '/Parser/TokenWalker.php';
require_once __DIR__ . '/Taint/TaintInfo.php';
require_once __DIR__ . '/Taint/TaintEngine.php';
require_once __DIR__ . '/Detectors/Finding.php';
require_once __DIR__ . '/Detectors/SQLInjection.php';
require_once __DIR__ . '/Reporter/ConsoleReporter.php';

use PHPSec\Parser\TokenWalker;
use PHPSec\Taint\TaintEngine;
use PHPSec\Detectors\Finding;
use PHPSec\Detectors\SQLInjection;

function phpsec_cache_path(): string
{
    return sys_get_temp_dir() . '/phpsec-last-scan.json';
}

function phpsec_save_cache(string $target, array $findings): void
{
    $data = [
        'target' => $target,
        'generatedAt' => date('c'),
        'findings' => array_map(fn(Finding $f) => $f->toArray(), $findings),
    ];
    file_put_contents(phpsec_cache_path(), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function phpsec_load_cache(): ?array
{
    $path = phpsec_cache_path();
    if (!file_exists($path)) {
        return null;
    }
    $data = json_decode(file_get_contents($path), true);
    return is_array($data) ? $data : null;
}

function phpsec_finding_from_array(array $row): Finding
{
    $f = new Finding();
    $f->id = $row['id'];
    $f->type = $row['type'];
    $f->severity = $row['severity'];
    $f->confidence = $row['confidence'];
    $f->file = $row['file'];
    $f->line = $row['line'];
    $f->source = $row['source'];
    $f->sink = $row['sink'];
    $f->flow = $row['flow'];
    $f->reason = $row['reason'];
    $f->recommendation = $row['recommendation'];
    return $f;
}

function phpsec_collect_php_files(string $target): array
{
    if (is_file($target)) {
        return [$target];
    }

    $ignore = ['vendor', 'node_modules', '.git', 'storage', 'cache', 'uploads'];
    $files = [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $fileInfo) {
        /** @var SplFileInfo $fileInfo */
        $path = $fileInfo->getPathname();

        foreach ($ignore as $dir) {
            if (strpos($path, DIRECTORY_SEPARATOR . $dir . DIRECTORY_SEPARATOR) !== false) {
                continue 2;
            }
        }

        if ($fileInfo->getExtension() === 'php') {
            $files[] = $path;
        }
    }

    sort($files);
    return $files;
}

/** @return array{0: Finding[], 1: int, 2: int} [findings, statementCount, sinkCallCount] */
function phpsec_scan_file(string $file): array
{
    $walker = new TokenWalker();
    $statements = $walker->parseFile($file);

    $engine = new TaintEngine();
    $taintMap = $engine->analyze($statements);

    $detector = new SQLInjection();
    $findings = $detector->detect($statements, $taintMap, $file);

    return [$findings, count($statements), $detector->getSinkCallCount()];
}

/**
 * Scan a file or directory. Returns structured result for CLI/JSON/web.
 *
 * @return array{
 *   target: string,
 *   findings: Finding[],
 *   stats: array{files: int, phpFiles: int, statements: int, sinkCalls: int},
 *   error?: string
 * }
 */
function phpsec_scan(string $target): array
{
    if (!file_exists($target)) {
        return [
            'target' => $target,
            'findings' => [],
            'stats' => ['files' => 0, 'phpFiles' => 0, 'statements' => 0, 'sinkCalls' => 0],
            'error' => 'Path does not exist.',
        ];
    }

    $real = realpath($target);
    if ($real === false) {
        return [
            'target' => $target,
            'findings' => [],
            'stats' => ['files' => 0, 'phpFiles' => 0, 'statements' => 0, 'sinkCalls' => 0],
            'error' => 'Could not resolve path.',
        ];
    }

    $phpFiles = phpsec_collect_php_files($real);
    $allFindings = [];
    $statementCount = 0;
    $sinkCallCount = 0;

    foreach ($phpFiles as $file) {
        [$findings, $stmtCount, $sinks] = phpsec_scan_file($file);
        array_push($allFindings, ...$findings);
        $statementCount += $stmtCount;
        $sinkCallCount += $sinks;
    }

    $totalFiles = is_file($real) ? 1 : iterator_count(new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($real, FilesystemIterator::SKIP_DOTS)
    ));

    phpsec_save_cache($real, $allFindings);

    return [
        'target' => $real,
        'findings' => $allFindings,
        'stats' => [
            'files' => $totalFiles,
            'phpFiles' => count($phpFiles),
            'statements' => $statementCount,
            'sinkCalls' => $sinkCallCount,
        ],
    ];
}

/** Default allowlisted root for the web folder browser (XAMPP htdocs). */
function phpsec_scan_root(): string
{
    $env = getenv('PHPSEC_SCAN_ROOT');
    if (is_string($env) && $env !== '' && is_dir($env)) {
        $real = realpath($env);
        return $real !== false ? $real : $env;
    }

    // Prefer XAMPP htdocs when this project lives under it.
    $htdocs = realpath(dirname(__DIR__, 2));
    if ($htdocs !== false && is_dir($htdocs)) {
        return $htdocs;
    }

    $fallback = realpath(dirname(__DIR__));
    return $fallback !== false ? $fallback : dirname(__DIR__);
}

/**
 * Resolve a user-supplied path under the scan root. Rejects escapes.
 * Returns absolute path or null if invalid.
 */
function phpsec_resolve_under_root(string $path, ?string $root = null): ?string
{
    $root = $root ?? phpsec_scan_root();
    $rootReal = realpath($root);
    if ($rootReal === false) {
        return null;
    }

    $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, trim($path));

    // Absolute path: must still stay under root.
    if (preg_match('#^[a-zA-Z]:\\\\#', $path) || str_starts_with($path, DIRECTORY_SEPARATOR)) {
        $candidate = $path;
    } else {
        $candidate = $rootReal . DIRECTORY_SEPARATOR . ltrim($path, DIRECTORY_SEPARATOR);
    }

    // Normalize without requiring the path to exist yet for listing parents.
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

    // Rebuild absolute path (Windows drive letter).
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
 * List directories (and optionally .php files) under a path for the folder browser.
 *
 * @return array{path: string, parent: ?string, entries: list<array{name: string, path: string, type: string}>}|array{error: string}
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
            $entries[] = [
                'name' => $name,
                'path' => $full,
                'type' => 'dir',
            ];
        } elseif ($includePhpFiles && is_file($full) && str_ends_with(strtolower($name), '.php')) {
            $entries[] = [
                'name' => $name,
                'path' => $full,
                'type' => 'file',
            ];
        }
    }

    usort($entries, function ($a, $b) {
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
