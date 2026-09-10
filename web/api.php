<?php
declare(strict_types=1);

/**
 * PHPSEC V2 web UI API — browse folders under the allowlisted scan root and run scans.
 */

require __DIR__ . '/../src/Autoload.php';
require __DIR__ . '/../src/Web/PathGuard.php';

use PHPSec\Config\Configuration;
use PHPSec\Engine\AnalysisEngine;

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_GET['action'] ?? $_POST['action'] ?? null;

if ($method === 'GET' && $action === 'root') {
    echo json_encode([
        'root' => phpsec_scan_root(),
        'default' => phpsec_scan_root(),
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($method === 'GET' && $action === 'browse') {
    $path = $_GET['path'] ?? phpsec_scan_root();
    $result = phpsec_list_directory(is_string($path) ? $path : phpsec_scan_root(), true);
    http_response_code(isset($result['error']) ? 400 : 200);
    echo json_encode($result, JSON_UNESCAPED_SLASHES);
    exit;
}

if ($method === 'POST' && $action === 'scan') {
    $raw = file_get_contents('php://input');
    $body = json_decode($raw ?: '[]', true);
    if (!is_array($body)) {
        $body = [];
    }

    $path = $body['path'] ?? ($_POST['path'] ?? '');
    if (!is_string($path) || trim($path) === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Missing path.']);
        exit;
    }

    $resolved = phpsec_resolve_under_root($path);
    if ($resolved === null || (!is_dir($resolved) && !is_file($resolved))) {
        http_response_code(400);
        echo json_encode(['error' => 'Path not found or outside the allowed scan root.']);
        exit;
    }

    if (is_file($resolved) && !str_ends_with(strtolower($resolved), '.php')) {
        http_response_code(400);
        echo json_encode(['error' => 'Only PHP files or directories can be scanned.']);
        exit;
    }

    try {
        $config = Configuration::load(dirname(__DIR__), $resolved);
        $engine = new AnalysisEngine($config);
        $result = $engine->scan($resolved);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Scan failed: ' . $e->getMessage()]);
        exit;
    }

    $stats = $result->stats;
    $findings = array_map(static function (array $row): array {
        // Web UI compatibility aliases
        $row['reason'] = $row['description'] ?? '';
        return $row;
    }, array_map(static fn ($f) => $f->toArray(), $result->findings->all()));

    echo json_encode([
        'target' => $resolved,
        'version' => '2.0',
        'stats' => [
            'files' => $stats['files'] ?? 0,
            'phpFiles' => $stats['files'] ?? 0,
            'statements' => $stats['statements'] ?? 0,
            'sources' => $stats['sources'] ?? 0,
            'sinks' => $stats['sinks'] ?? 0,
            'functions' => $stats['functions'] ?? 0,
            'sinkCalls' => $stats['sinks'] ?? 0,
            'duration' => $result->durationSeconds,
        ],
        'findings' => $findings,
        'severity' => $result->findings->countBySeverity(),
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

http_response_code(400);
echo json_encode([
    'error' => 'Unknown action. Use action=root|browse|scan.',
]);
