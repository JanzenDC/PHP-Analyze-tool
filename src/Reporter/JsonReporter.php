<?php
declare(strict_types=1);

namespace PHPSec\Reporter;

use PHPSec\Scanner\ScanResult;

final class JsonReporter
{
    public function render(ScanResult $result, string $target): string
    {
        return (string) json_encode([
            'version' => '2.0',
            'target' => $target,
            'generated_at' => gmdate('c'),
            ...$result->toArray(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    }
}
