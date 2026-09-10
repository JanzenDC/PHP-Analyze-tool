#!/usr/bin/env php
<?php

/**
 * PHPSEC — Native PHP Security Analyzer (V1)
 *
 * Usage:
 *   php phpsec.php scan <file-or-directory> [--json]
 *   php phpsec.php show <FINDING-ID>          (reads the last scan's cache)
 *   php phpsec.php flow <FINDING-ID>          (ASCII data-flow diagram)
 *
 * V1 scope: SQL Injection only, single-file, linear (no branch/loop
 * modeling), no cross-file taint tracking. See README.md.
 */

require __DIR__ . '/src/lib.php';

use PHPSec\Reporter\ConsoleReporter;

// ---- CLI dispatch ----

$args = $argv;
array_shift($args); // script name

$command = $args[0] ?? null;
$reporter = new ConsoleReporter();

if ($command === 'scan') {
    $asJson = in_array('--json', $args, true);
    $target = $args[1] ?? null;

    if ($target === null || !file_exists($target)) {
        fwrite(STDERR, "Usage: php phpsec.php scan <file-or-directory> [--json]\n");
        exit(1);
    }

    $phpFiles = phpsec_collect_php_files($target);

    $allFindings = [];
    $statementCount = 0;
    $sinkCallCount = 0;
    $totalPhp = count($phpFiles);

    if (!$asJson) {
        $reporter->printHeader($target);
        $reporter->progress(0, max($totalPhp, 1));
    }

    foreach ($phpFiles as $i => $file) {
        [$findings, $stmtCount, $sinks] = phpsec_scan_file($file);
        array_push($allFindings, ...$findings);
        $statementCount += $stmtCount;
        $sinkCallCount += $sinks;

        if (!$asJson) {
            $reporter->progress($i + 1, max($totalPhp, 1));
        }
    }

    $totalFiles = is_file($target) ? 1 : iterator_count(new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS)
    ));

    phpsec_save_cache($target, $allFindings);

    if ($asJson) {
        echo json_encode(array_map(fn($f) => $f->toArray(), $allFindings), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        exit(empty($allFindings) ? 0 : 2);
    }

    $reporter->printStats([
        'Files' => $totalFiles,
        'PHP Files' => $totalPhp,
        'Statements' => $statementCount,
        'Sink calls checked' => $sinkCallCount,
    ]);

    $reporter->printFindingsSummary($allFindings);

    if (!empty($allFindings)) {
        $reporter->printFindingsDetail($allFindings);
    }

    $reporter->printRunHints($allFindings);

    exit(empty($allFindings) ? 0 : 2);
}

if ($command === 'show' || $command === 'flow') {
    $id = $args[1] ?? null;
    if ($id === null) {
        fwrite(STDERR, "Usage: php phpsec.php {$command} <FINDING-ID>\n");
        exit(1);
    }

    $cache = phpsec_load_cache();
    if ($cache === null) {
        fwrite(STDERR, "No scan cache found. Run `php phpsec.php scan <path>` first.\n");
        exit(1);
    }

    $match = null;
    foreach ($cache['findings'] as $row) {
        if ($row['id'] === $id) {
            $match = $row;
            break;
        }
    }

    if ($match === null) {
        fwrite(STDERR, "Finding {$id} not found in the last scan (" . ($cache['target'] ?? '?') . ").\n");
        exit(1);
    }

    $finding = phpsec_finding_from_array($match);

    if ($command === 'show') {
        $reporter->printOneFinding($finding);
    } else {
        $reporter->printFlowDiagram($finding);
    }
    exit(0);
}

fwrite(STDERR, "Usage:\n  php phpsec.php scan <file-or-directory> [--json]\n  php phpsec.php show <FINDING-ID>\n  php phpsec.php flow <FINDING-ID>\n");
exit(1);
