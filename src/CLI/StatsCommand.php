<?php
declare(strict_types=1);

namespace PHPSec\CLI;

final class StatsCommand extends Command
{
    public function name(): string { return 'stats'; }
    public function description(): string { return 'Show statistics from the last scan'; }
    public function usage(): string { return 'Usage: php phpsec.php stats'; }

    public function execute(array $arguments, bool $quiet = false, bool $color = true): int
    {
        if ($arguments !== []) { return $this->error($this->usage()); }
        $cache = $this->loadCache();
        if ($cache === null) { return $this->error('No scan cache found. Run scan first.'); }
        if ($quiet) { return 0; }
        echo "Last scan: " . ($cache['target'] ?? '?') . "\n";
        foreach (($cache['stats'] ?? []) as $name => $value) {
            printf("  %-14s %s\n", ucfirst((string) $name) . ':', (string) $value);
        }
        printf("  %-14s %d\n", 'Findings:', count($cache['findings'] ?? []));
        printf("  %-14s %.3fs\n", 'Duration:', (float) ($cache['duration_seconds'] ?? 0));
        return 0;
    }
}
