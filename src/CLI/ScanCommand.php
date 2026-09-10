<?php
declare(strict_types=1);

namespace PHPSec\CLI;

use PHPSec\Config\Configuration;
use PHPSec\Engine\AnalysisEngine;
use PHPSec\Reporter\ConsoleReporter;
use PHPSec\Reporter\HtmlReporter;
use PHPSec\Reporter\JsonReporter;
use PHPSec\Reporter\SarifReporter;

final class ScanCommand extends Command
{
    public function name(): string { return 'scan'; }
    public function description(): string { return 'Scan a PHP file or project'; }
    public function usage(): string
    {
        return 'Usage: php phpsec.php scan <path> [--deep] [--json] [--html[=file]] [--sarif[=file]]'
            . ' [--severity=LEVEL] [--confidence=LEVEL] [--exclude=PATTERN] [--quiet] [--no-color]';
    }

    public function execute(array $arguments, bool $quiet = false, bool $color = true): int
    {
        $target = null; $json = false; $html = null; $sarif = null; $deep = false;
        $severity = null; $confidence = null; $exclude = ['vendor', '.git', 'node_modules'];
        foreach ($arguments as $argument) {
            if ($argument === '--deep') { $deep = true; continue; }
            if ($argument === '--json') { $json = true; continue; }
            if ($argument === '--html' || str_starts_with($argument, '--html=')) {
                $html = str_contains($argument, '=') ? substr($argument, strpos($argument, '=') + 1) : 'phpsec-report.html';
                continue;
            }
            if ($argument === '--sarif' || str_starts_with($argument, '--sarif=')) {
                $sarif = str_contains($argument, '=') ? substr($argument, strpos($argument, '=') + 1) : 'phpsec-results.sarif';
                continue;
            }
            if (str_starts_with($argument, '--severity=')) { $severity = strtoupper(substr($argument, 11)); continue; }
            if (str_starts_with($argument, '--confidence=')) { $confidence = strtoupper(substr($argument, 13)); continue; }
            if (str_starts_with($argument, '--exclude=')) {
                $exclude = [...$exclude, ...array_filter(array_map('trim', explode(',', substr($argument, 10))))];
                continue;
            }
            if (str_starts_with($argument, '-')) { return $this->error("Unknown option: {$argument}"); }
            if ($target !== null) { return $this->error('Only one scan path may be supplied.'); }
            $target = $argument;
        }
        if ($target === null) { return $this->error($this->usage()); }
        if (!file_exists($target)) { return $this->error("Path not found: {$target}"); }
        if ($severity !== null && !in_array($severity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], true)) {
            return $this->error("Invalid severity: {$severity}");
        }
        if ($confidence !== null && !in_array($confidence, ['HIGH', 'MEDIUM', 'LOW'], true)) {
            return $this->error("Invalid confidence: {$confidence}");
        }

        $configured = Configuration::load(dirname(__DIR__, 2), $target);
        $configuration = new Configuration(
            array_values(array_unique([...$configured->exclude, ...$exclude])),
            $severity ?? ($deep ? 'INFO' : $configured->minimumSeverity),
            $confidence ?? ($deep ? 'LOW' : $configured->minimumConfidence),
            $configured->rules,
            $configured->scanRoot,
        );
        $result = (new AnalysisEngine($configuration))->scan($target);
        $cache = [
            'version' => '2.0', 'target' => $target, 'generated_at' => gmdate('c'),
            ...$result->toArray(),
        ];
        if (@file_put_contents($this->cachePath(), json_encode($cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) === false) {
            return $this->error('Unable to save the last-scan cache.');
        }

        if ($html !== null) {
            if (@file_put_contents($html, (new HtmlReporter())->render($result, $target)) === false) {
                return $this->error("Unable to write HTML report: {$html}");
            }
        }
        if ($sarif !== null) {
            if (@file_put_contents($sarif, (new SarifReporter())->render($result)) === false) {
                return $this->error("Unable to write SARIF report: {$sarif}");
            }
        }
        if (!$quiet) {
            echo $json
                ? (new JsonReporter())->render($result, $target)
                : (new ConsoleReporter($color))->render($result, $target);
            if (!$json && $html !== null) { echo "HTML report: {$html}\n"; }
            if (!$json && $sarif !== null) { echo "SARIF report: {$sarif}\n"; }
        }
        return $result->findings->count() === 0 ? 0 : 2;
    }
}
