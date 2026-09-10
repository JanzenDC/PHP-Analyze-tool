<?php
declare(strict_types=1);

namespace PHPSec\Detectors;

use PHPSec\Taint\TaintValue;

final class PathTraversalDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $findings = [];
        $names = ['file_get_contents', 'file_put_contents', 'fopen', 'readfile', 'unlink', 'rename', 'copy'];
        foreach ($statements as $statement) {
            foreach ($this->expressions->calls($statement->tokens, $file, $statement->line) as $call) {
                if (!in_array($call->name, $names, true)) {
                    continue;
                }
                foreach ($call->args as $arg) {
                    $value = $this->value($arg, $taintMap);
                    if ($value === null || !$value->isTaintedFor('path')) {
                        continue;
                    }
                    // Prefer SSRF when the flow clearly looks like a URL fetch.
                    if ($call->name === 'file_get_contents' && $this->looksLikeUrlFlow($value)) {
                        continue;
                    }
                    $findings[] = $this->finding(
                        'Path Traversal',
                        'MEDIUM',
                        $call->isMethod ? 'MEDIUM' : 'HIGH',
                        $file,
                        $statement,
                        $value,
                        $call->name,
                        'Tainted input controls a filesystem path.',
                        'Files outside the intended directory may be accessed or changed.',
                        'Resolve against an allowlisted base directory and validate the canonical path.'
                    );
                    break;
                }
            }
        }
        return $findings;
    }

    private function looksLikeUrlFlow(TaintValue $value): bool
    {
        $hay = strtolower($value->sourceExpr . ' ' . implode(' ', $value->flow));
        foreach (['url', 'uri', 'endpoint', 'http', 'https', 'webhook'] as $hint) {
            if (str_contains($hay, $hint)) {
                return true;
            }
        }
        return false;
    }
}
