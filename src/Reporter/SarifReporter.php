<?php
declare(strict_types=1);

namespace PHPSec\Reporter;

use PHPSec\Scanner\ScanResult;

final class SarifReporter
{
    public function render(ScanResult $result): string
    {
        $rules = [];
        $results = [];
        foreach ($result->findings as $finding) {
            $ruleId = strtolower((string) preg_replace('/[^a-z0-9]+/i', '-', $finding->type));
            $rules[$ruleId] = [
                'id' => $ruleId,
                'name' => $finding->type,
                'shortDescription' => ['text' => $finding->description],
                'help' => ['text' => $finding->recommendation],
            ];
            $results[] = [
                'ruleId' => $ruleId,
                'level' => match ($finding->severity) {
                    'CRITICAL', 'HIGH' => 'error', 'MEDIUM' => 'warning', default => 'note'
                },
                'message' => ['text' => "{$finding->id}: {$finding->description}"],
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => str_replace('\\', '/', $finding->file)],
                        'region' => ['startLine' => max(1, $finding->line)],
                    ],
                ]],
            ];
        }
        return (string) json_encode([
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => ['name' => 'PHPSEC', 'version' => '2.0', 'rules' => array_values($rules)]],
                'results' => $results,
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }
}
