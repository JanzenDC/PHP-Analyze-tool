<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoload.php';

use PHPSec\Engine\AnalysisEngine;

$engine = new AnalysisEngine();
foreach (['sql_injection_vuln.php', 'sql_injection_safe.php'] as $fixture) {
    $result = $engine->scan(__DIR__ . '/Fixtures/' . $fixture);
    echo $fixture . ': ' . $result->findings->count() . " findings\n";
}
