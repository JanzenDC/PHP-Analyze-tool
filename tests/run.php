<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoload.php';

use PHPSec\Engine\AnalysisEngine;

$cases = [
    'sql_injection_vuln.php' => ['present' => ['SQL Injection']],
    'sql_injection_safe.php' => ['absent' => ['SQL Injection']],
    'xss_vuln.php' => ['present' => ['Cross-Site Scripting']],
    'xss_safe.php' => ['absent' => ['Cross-Site Scripting']],
    'command_injection_vuln.php' => ['present' => ['Command Injection']],
    'command_injection_safe.php' => ['absent' => ['Command Injection']],
    'path_traversal_vuln.php' => ['present' => ['Path Traversal']],
    'file_inclusion_vuln.php' => ['present' => ['File Inclusion']],
    'ssrf_vuln.php' => ['present' => ['Server-Side Request Forgery'], 'absent' => ['Path Traversal']],
    'dangerous_eval.php' => ['present' => ['Dangerous Function Usage']],
    'hardcoded_secret.php' => ['present' => ['Hardcoded Secret']],
    'upload_risky.php' => ['present' => ['Unsafe File Upload']],
];

$engine = new AnalysisEngine();
$failures = 0;
foreach ($cases as $file => $expectations) {
    $result = $engine->scan(__DIR__ . '/Fixtures/' . $file);
    $types = array_map(static fn($finding): string => $finding->type, $result->findings->all());
    $errors = [];
    foreach ($expectations['present'] ?? [] as $type) {
        if (!in_array($type, $types, true)) { $errors[] = "missing {$type}"; }
    }
    foreach ($expectations['absent'] ?? [] as $type) {
        if (in_array($type, $types, true)) { $errors[] = "unexpected {$type}"; }
    }
    if ($errors === []) {
        echo "PASS  {$file}\n";
    } else {
        echo "FAIL  {$file}: " . implode(', ', $errors) . ' (got: ' . implode(', ', $types) . ")\n";
        $failures++;
    }
}

printf("\n%d passed, %d failed\n", count($cases) - $failures, $failures);
exit($failures === 0 ? 0 : 1);
