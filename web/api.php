<?php

/**
 * PHPSEC web UI API — browse folders under the allowlisted scan root and run scans.
 */

require __DIR__ . '/../src/lib.php';

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
    $result = phpsec_list_directory($path, true);
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

    $result = phpsec_scan($resolved);
    if (isset($result['error'])) {
        http_response_code(400);
        echo json_encode(['error' => $result['error']]);
        exit;
    }

    echo json_encode([
        'target' => $result['target'],
        'stats' => $result['stats'],
        'findings' => array_map(fn($f) => $f->toArray(), $result['findings']),
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

http_response_code(400);
echo json_encode([
    'error' => 'Unknown action. Use action=root|browse|scan.',
]);
