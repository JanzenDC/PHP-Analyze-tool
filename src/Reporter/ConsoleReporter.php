<?php

namespace PHPSec\Reporter;

use PHPSec\Detectors\Finding;

/**
 * Renders scan results as a colored terminal report, plus the plain
 * ASCII "flow" diagram used by `phpsec.php flow <ID>`.
 *
 * Color is auto-disabled when stdout isn't a TTY (e.g. piped to a file
 * or CI log) so reports stay readable, or force-enabled via
 * PHPSEC_FORCE_COLOR=1 for demos.
 */
class ConsoleReporter
{
    private bool $color;

    private const RESET = "\033[0m";
    private const BOLD = "\033[1m";
    private const DIM = "\033[2m";
    private const RED = "\033[31m";
    private const GREEN = "\033[32m";
    private const YELLOW = "\033[33m";
    private const CYAN = "\033[36m";
    private const MAGENTA = "\033[35m";
    private const GRAY = "\033[90m";
    private const BOLD_RED = "\033[1;31m";

    public function __construct(?bool $color = null)
    {
        if ($color === null) {
            $color = getenv('PHPSEC_FORCE_COLOR') === '1'
                || (function_exists('posix_isatty') && posix_isatty(STDOUT));
        }
        $this->color = $color;
    }

    private function c(string $code, string $text): string
    {
        return $this->color ? $code . $text . self::RESET : $text;
    }

    public function printHeader(string $target): void
    {
        echo $this->c(self::BOLD, '🛡  PHPSEC') . $this->c(self::GRAY, '  — Native PHP Security Analyzer  v1.0') . "\n";
        echo $this->c(self::DIM, "   scan {$target}") . "\n\n";
    }

    /**
     * Draws a single progress bar line, overwriting itself via \r.
     * Call with $done === $total on the final call to leave a newline.
     */
    public function progress(int $done, int $total, string $label = 'Analyzing data flows'): void
    {
        $total = max($total, 1);
        $pct = (int) round(($done / $total) * 100);
        $width = 30;
        $filled = (int) round(($pct / 100) * $width);
        $bar = str_repeat('█', $filled) . str_repeat('░', $width - $filled);

        $line = sprintf("%s\n%s %3d%%", $label, $this->c(self::CYAN, $bar), $pct);
        // Move cursor up 1 line on repeat draws so we redraw the bar in place.
        static $drawnOnce = false;
        if ($drawnOnce) {
            echo "\033[1A\r\033[2K";
        }
        echo $line . ($done >= $total ? "\n\n" : "\n");
        $drawnOnce = $done < $total;
    }

    public function printStats(array $stats): void
    {
        $labelWidth = max(array_map('strlen', array_keys($stats))) + 2;
        foreach ($stats as $label => $value) {
            $dots = str_repeat('.', max(1, 24 - strlen($label)));
            echo sprintf("%s %s %s\n", $label, $this->c(self::DIM, $dots), $this->c(self::BOLD, (string) $value));
        }
        echo "\n";
    }

    /**
     * @param Finding[] $findings
     */
    public function printFindingsSummary(array $findings): void
    {
        $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
        foreach ($findings as $f) {
            $sev = strtoupper($f->severity);
            if (isset($counts[$sev])) {
                $counts[$sev]++;
            }
        }

        echo $this->c(self::BOLD, 'Findings') . ' ' . $this->c(self::DIM, str_repeat('─', 40)) . "\n";
        echo $this->severityLabel('CRITICAL', $counts['CRITICAL']) . '  '
            . $this->severityLabel('HIGH', $counts['HIGH']) . '  '
            . $this->severityLabel('MEDIUM', $counts['MEDIUM']) . '  '
            . $this->severityLabel('LOW', $counts['LOW']) . "\n\n";
    }

    private function severityLabel(string $name, int $count): string
    {
        $colorMap = [
            'CRITICAL' => self::BOLD_RED,
            'HIGH' => self::RED,
            'MEDIUM' => self::YELLOW,
            'LOW' => self::GRAY,
        ];
        return $this->c($colorMap[$name], "{$name} {$count}");
    }

    /**
     * @param Finding[] $findings
     */
    public function printFindingsDetail(array $findings): void
    {
        foreach ($findings as $finding) {
            $this->printOneFinding($finding);
        }
    }

    public function printOneFinding(Finding $finding): void
    {
        $sevColor = match (strtoupper($finding->severity)) {
            'CRITICAL' => self::BOLD_RED,
            'HIGH' => self::RED,
            'MEDIUM' => self::YELLOW,
            default => self::GRAY,
        };

        echo $this->c($sevColor, "[{$finding->severity}]") . ' ' . $this->c(self::BOLD, $finding->type)
            . $this->c(self::DIM, "  ({$finding->id}, confidence: {$finding->confidence})") . "\n";
        echo $this->c(self::DIM, "File: {$finding->file}:{$finding->line}") . "\n\n";

        echo $this->c(self::MAGENTA, 'SOURCE') . "\n  " . ($finding->source ?? 'unknown') . "\n\n";
        echo $this->c(self::MAGENTA, 'FLOW') . "\n" . $this->renderFlowLine($finding) . "\n\n";
        echo $this->c(self::MAGENTA, 'SINK') . "\n  {$finding->sink}\n\n";
        echo $this->c(self::MAGENTA, 'WHY') . "\n  {$finding->reason}\n\n";
        echo $this->c(self::GREEN, 'RECOMMENDATION') . "\n  {$finding->recommendation}\n";
        echo $this->c(self::DIM, str_repeat('─', 48)) . "\n\n";
    }

    private function renderFlowLine(Finding $finding): string
    {
        $hops = array_merge($finding->flow, [$finding->sink]);
        return '  ' . implode("\n    ↓\n  ", $hops);
    }

    /** Full ASCII vertical flow diagram used by `phpsec.php flow <ID>` */
    public function printFlowDiagram(Finding $finding): void
    {
        echo $this->c(self::BOLD, $finding->id) . "\n";
        echo $this->c(self::RED, $finding->type) . "\n\n";
        echo $this->c(self::DIM, "{$finding->file}:{$finding->line}") . "\n\n";

        $hops = array_merge($finding->flow, [$finding->sink]);
        foreach ($hops as $i => $hop) {
            echo "  {$hop}\n";
            if ($i < count($hops) - 1) {
                echo "     │\n     ▼\n";
            }
        }
        echo "     │\n     ▼\n  DATABASE\n";
    }

    /**
     * @param Finding[] $findings
     */
    public function printRunHints(array $findings): void
    {
        if (empty($findings)) {
            return;
        }
        $first = $findings[0]->id;
        echo $this->c(self::DIM, 'Run:') . "\n";
        echo "  php phpsec.php show {$first}    " . $this->c(self::DIM, '— full finding detail') . "\n";
        echo "  php phpsec.php flow {$first}    " . $this->c(self::DIM, '— ASCII data-flow diagram') . "\n";
    }
}
