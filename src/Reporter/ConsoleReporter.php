<?php
declare(strict_types=1);

namespace PHPSec\Reporter;

use PHPSec\Scanner\ScanResult;

final class ConsoleReporter
{
    public function __construct(private readonly bool $color = true) {}

    public function render(ScanResult $result, string $target): string
    {
        $counts = $result->findings->countBySeverity();
        $out = $this->bold("PHPSEC 2.0 — Security Scan") . "\n";
        $out .= "Target: {$target}\n" . str_repeat('─', 68) . "\n";
        $out .= sprintf(
            "Files: %d  Statements: %d  Sources: %d  Sinks: %d  Time: %.3fs\n",
            $result->stats['files'] ?? 0,
            $result->stats['statements'] ?? 0,
            $result->stats['sources'] ?? 0,
            $result->stats['sinks'] ?? 0,
            $result->durationSeconds
        );
        $out .= sprintf(
            "Findings: %d  CRITICAL %d  HIGH %d  MEDIUM %d  LOW %d  INFO %d\n",
            $result->findings->count(),
            $counts['CRITICAL'], $counts['HIGH'], $counts['MEDIUM'], $counts['LOW'], $counts['INFO']
        );

        foreach ($result->findings as $finding) {
            $out .= "\n" . $this->severity("[{$finding->severity}]", $finding->severity)
                . " {$finding->id}  {$finding->type} ({$finding->confidence} confidence)\n";
            $out .= "  {$finding->file}:{$finding->line}\n";
            $out .= "  {$finding->description}\n";
            $out .= "  Sink: {$finding->sink}";
            if ($finding->source !== null) {
                $out .= "  Source: {$finding->source}";
            }
            $out .= "\n  Fix: {$finding->recommendation}\n";
        }
        $out .= "\n" . ($result->findings->count() === 0 ? $this->green('No findings.') : 'Review findings before deployment.') . "\n";
        return $out;
    }

    private function bold(string $text): string { return $this->color ? "\033[1m{$text}\033[0m" : $text; }
    private function green(string $text): string { return $this->color ? "\033[32m{$text}\033[0m" : $text; }
    private function severity(string $text, string $severity): string
    {
        if (!$this->color) { return $text; }
        $code = match ($severity) { 'CRITICAL', 'HIGH' => 31, 'MEDIUM' => 33, 'LOW' => 36, default => 37 };
        return "\033[{$code}m{$text}\033[0m";
    }
}
