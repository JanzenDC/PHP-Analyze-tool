<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class SQLInjectionDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        return $this->scanCalls($file, $statements, $taintMap, ['mysqli_query', 'mysqli_multi_query', 'query', 'exec'], 'sql', 'SQL Injection', 'HIGH', 'Tainted input reaches a SQL execution API.', 'An attacker may read or modify database data.', 'Use prepared statements with bound parameters.', static fn($call) => in_array($call->name, ['mysqli_query', 'mysqli_multi_query'], true) ? array_slice($call->args, 1, 1) : array_slice($call->args, 0, 1));
    }
}
