<?php
declare(strict_types=1);

namespace PHPSec\Detectors;

use PHPSec\Findings\Finding;
use PHPSec\Parser\ExpressionParser;
use PHPSec\Parser\Statement;
use PHPSec\Taint\TaintEngine;
use PHPSec\Taint\TaintValue;

abstract class AbstractDetector implements DetectorInterface
{
    protected int $counter = 0;
    protected ExpressionParser $expressions;
    protected TaintEngine $taint;
    public function __construct() { $this->expressions = new ExpressionParser(); $this->taint = new TaintEngine(); }
    protected function value(array $tokens, array $map): ?TaintValue { return $this->taint->taintForTokens($tokens, $map); }
    protected function scanCalls(string $file, array $statements, array $map, array $names, string $context, string $type, string $severity, string $description, string $impact, string $recommendation, ?callable $argumentSelector = null): array
    {
        $findings = [];
        foreach ($statements as $statement) {
            foreach ($this->expressions->calls($statement->tokens, $file, $statement->line) as $call) {
                if (!in_array($call->name, $names, true)) { continue; }
                $args = $argumentSelector ? $argumentSelector($call) : $call->args;
                foreach ($args as $arg) {
                    $value = $this->value($arg, $map);
                    if ($value !== null && $value->isTaintedFor($context)) {
                        $findings[] = $this->finding($type, $severity, $call->isMethod ? 'MEDIUM' : 'HIGH', $file, $statement, $value, $call->name, $description, $impact, $recommendation);
                        break;
                    }
                }
            }
        }
        return $findings;
    }
    protected function finding(string $type, string $severity, string $confidence, string $file, Statement $statement, ?TaintValue $value, string $sink, string $description, string $impact, string $recommendation): Finding
    {
        $this->counter++;
        return new Finding('', $type, $severity, $confidence, $file, $statement->line, $value?->sourceExpr, $sink, $value?->flow ?? [], $description, $impact, $recommendation, [trim($statement->text())]);
    }
}
