<?php
declare(strict_types=1);

namespace PHPSec\CLI;

final class FlowCommand extends Command
{
    public function name(): string { return 'flow'; }
    public function description(): string { return 'Show a cached finding data flow'; }
    public function usage(): string { return 'Usage: php phpsec.php flow PHPSEC-001'; }

    public function execute(array $arguments, bool $quiet = false, bool $color = true): int
    {
        $id = $arguments[0] ?? null;
        if ($id === null) { return $this->error($this->usage()); }
        $cache = $this->loadCache();
        if ($cache === null) { return $this->error('No scan cache found. Run scan first.'); }
        foreach ($cache['findings'] ?? [] as $finding) {
            if (($finding['id'] ?? '') !== $id) { continue; }
            if ($quiet) { return 0; }
            echo "{$id} — {$finding['type']}\n";
            $flow = $finding['flow'] ?? [];
            if ($flow === []) {
                echo "[source unavailable]\n   |\n   v\n[{$finding['sink']}] {$finding['file']}:{$finding['line']}\n";
            } else {
                $flow[] = "{$finding['sink']} at {$finding['file']}:{$finding['line']}";
                echo implode("\n   |\n   v\n", array_map(static fn(string $step): string => "[{$step}]", $flow)) . "\n";
            }
            return 0;
        }
        return $this->error("Finding not found: {$id}");
    }
}
