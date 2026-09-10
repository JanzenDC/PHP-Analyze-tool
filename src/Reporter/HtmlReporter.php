<?php
declare(strict_types=1);

namespace PHPSec\Reporter;

use PHPSec\Scanner\ScanResult;

final class HtmlReporter
{
    public function render(ScanResult $result, string $target): string
    {
        $h = static fn(mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $counts = $result->findings->countBySeverity();
        $cards = '';
        foreach ($counts as $severity => $count) {
            $cards .= '<div class="metric ' . strtolower($severity) . '"><b>' . $h($count) . '</b><span>' . $h($severity) . '</span></div>';
        }
        $findings = '';
        foreach ($result->findings as $finding) {
            $flow = $finding->flow === [] ? '' : '<pre>' . $h(implode("\n↓\n", $finding->flow)) . '</pre>';
            $context = $finding->codeContext === [] ? '' : '<pre><code>' . $h(implode("\n", $finding->codeContext)) . '</code></pre>';
            $findings .= '<article><header><span class="badge ' . strtolower($finding->severity) . '">' . $h($finding->severity) . '</span>'
                . '<h2>' . $h($finding->id . ' — ' . $finding->type) . '</h2></header>'
                . '<p class="location">' . $h($finding->file . ':' . $finding->line) . ' · ' . $h($finding->confidence) . ' confidence</p>'
                . '<p>' . $h($finding->description) . '</p><p><b>Impact:</b> ' . $h($finding->impact) . '</p>'
                . '<p><b>Recommendation:</b> ' . $h($finding->recommendation) . '</p>' . $flow . $context . '</article>';
        }
        if ($findings === '') {
            $findings = '<article><h2>No findings</h2><p>No enabled rule matched the scanned source.</p></article>';
        }

        $templateFile = dirname(__DIR__, 2) . '/templates/report.html';
        $template = is_file($templateFile) ? (string) file_get_contents($templateFile) : self::template();
        return strtr($template, [
            '{{TARGET}}' => $h($target),
            '{{GENERATED_AT}}' => $h(gmdate('c')),
            '{{TOTAL}}' => $h($result->findings->count()),
            '{{FILES}}' => $h($result->stats['files'] ?? 0),
            '{{DURATION}}' => $h(number_format($result->durationSeconds, 3)),
            '{{SEVERITY_CARDS}}' => $cards,
            '{{FINDINGS}}' => $findings,
        ]);
    }

    private static function template(): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><title>PHPSEC report</title></head><body>{{FINDINGS}}</body></html>';
    }
}
