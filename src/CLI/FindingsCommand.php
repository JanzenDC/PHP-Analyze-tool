<?php
declare(strict_types=1);

namespace PHPSec\CLI;

final class FindingsCommand extends Command
{
    public function name(): string { return 'findings'; }
    public function description(): string { return 'List findings from the last scan'; }
    public function usage(): string { return 'Usage: php phpsec.php findings [--severity=LEVEL] [--type=TEXT]'; }

    public function execute(array $arguments, bool $quiet = false, bool $color = true): int
    {
        $cache = $this->loadCache();
        if ($cache === null) { return $this->error('No scan cache found. Run scan first.'); }
        $severity = null; $type = null;
        foreach ($arguments as $argument) {
            if (str_starts_with($argument, '--severity=')) { $severity = strtoupper(substr($argument, 11)); }
            elseif (str_starts_with($argument, '--type=')) { $type = substr($argument, 7); }
            else { return $this->error("Unknown filter: {$argument}"); }
        }
        if ($quiet) { return 0; }
        $count = 0;
        foreach ($cache['findings'] ?? [] as $finding) {
            if ($severity !== null && strtoupper((string) ($finding['severity'] ?? '')) !== $severity) { continue; }
            if ($type !== null && stripos((string) ($finding['type'] ?? ''), $type) === false) { continue; }
            printf("%-11s %-8s %-28s %s:%d\n", $finding['id'], $finding['severity'], $finding['type'], $finding['file'], $finding['line']);
            $count++;
        }
        echo "{$count} finding(s)\n";
        return 0;
    }
}
