<?php

namespace PHPSec\Detectors;

use PHPSec\Parser\Statement;
use PHPSec\Taint\TaintInfo;

/**
 * Flags tainted data reaching a SQL execution sink without going
 * through a query-building sanitizer in between.
 *
 * Recognized sinks (V1):
 *   - mysqli_query(...) / mysqli_multi_query(...)
 *   - ->query(...) / ->exec(...)   (heuristic: any `->query()`/`->exec()`
 *     call is treated as a PDO-style sink. This over-approximates --
 *     it will also match a `->query()` method on an unrelated class --
 *     which is a deliberate false-positive-over-false-negative tradeoff
 *     for a security tool. Document this in output as "confidence".)
 *
 * A finding is raised only when an argument to the sink is a variable
 * that TaintEngine marked as tainted (i.e. traced back to $_GET/$_POST/
 * etc. with no sanitizer/cast seen along the way).
 */
class SQLInjection
{
    private const FUNCTION_SINKS = ['mysqli_query', 'mysqli_multi_query'];
    private const METHOD_SINKS = ['query', 'exec'];

    private int $findingCounter = 0;
    private int $sinkCallCount = 0;

    /** Total sink call sites inspected (tainted or not) across the last detect() run. */
    public function getSinkCallCount(): int
    {
        return $this->sinkCallCount;
    }

    /**
     * @param Statement[] $statements
     * @param array<string, TaintInfo> $taintMap
     * @return Finding[]
     */
    public function detect(array $statements, array $taintMap, string $file): array
    {
        $findings = [];

        foreach ($statements as $stmt) {
            $sinkCalls = $this->findSinkCalls($stmt->tokens);
            $this->sinkCallCount += count($sinkCalls);

            foreach ($sinkCalls as $call) {
                [$sinkLabel, $argTokens, $confidence] = $call;
                $taintedVar = $this->firstTaintedVariable($argTokens, $taintMap);

                if ($taintedVar === null) {
                    continue;
                }

                $info = $taintMap[$taintedVar];
                $this->findingCounter++;

                $finding = new Finding();
                $finding->id = sprintf('PHPSEC-%03d', $this->findingCounter);
                $finding->type = 'SQL Injection';
                $finding->severity = 'HIGH';
                $finding->confidence = $confidence;
                $finding->file = $file;
                $finding->line = $stmt->line;
                $finding->source = $info->sourceExpr;
                $finding->sink = $sinkLabel;
                $finding->flow = $info->flow;
                $finding->reason = 'User-controlled input reaches a SQL execution sink '
                    . 'without a parameterized query or recognized sanitizer in between.';
                $finding->recommendation = 'Use prepared statements with bound parameters '
                    . '(PDO::prepare()/execute() or mysqli prepared statements) instead of '
                    . 'building the query string with concatenation or interpolation.';

                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @return array{0: string, 1: array, 2: string}[] list of [sinkLabel, argTokens, confidence]
     */
    private function findSinkCalls(array $tokens): array
    {
        $calls = [];
        $n = count($tokens);

        for ($i = 0; $i < $n; $i++) {
            $token = $tokens[$i];
            if (!is_array($token)) {
                continue;
            }

            // Function-style sink: mysqli_query(...)
            if ($token[0] === T_STRING && in_array($token[1], self::FUNCTION_SINKS, true)) {
                $next = $tokens[$i + 1] ?? null;
                if ((is_array($next) ? $next[1] : $next) === '(') {
                    $args = $this->captureArgs($tokens, $i + 1);
                    $calls[] = [$token[1] . '()', $args, 'HIGH'];
                }
                continue;
            }

            // Method-style sink: ->query(...) / ->exec(...)
            if ($token[0] === T_OBJECT_OPERATOR) {
                $methodTok = $tokens[$i + 1] ?? null;
                if (is_array($methodTok) && $methodTok[0] === T_STRING
                    && in_array($methodTok[1], self::METHOD_SINKS, true)) {
                    $parenTok = $tokens[$i + 2] ?? null;
                    if ((is_array($parenTok) ? $parenTok[1] : $parenTok) === '(') {
                        $args = $this->captureArgs($tokens, $i + 2);
                        // Lower confidence: we can't confirm the receiver is a PDO instance
                        // without cross-file type resolution (out of scope for V1).
                        $calls[] = ['->' . $methodTok[1] . '()', $args, 'MEDIUM'];
                    }
                }
            }
        }

        return $calls;
    }

    private function captureArgs(array $tokens, int $openParenIndex): array
    {
        $n = count($tokens);
        $depth = 0;
        $args = [];
        for ($j = $openParenIndex; $j < $n; $j++) {
            $t = $tokens[$j];
            $text = is_array($t) ? $t[1] : $t;
            if ($text === '(') {
                $depth++;
                if ($depth === 1) {
                    continue; // don't include the opening paren itself
                }
            } elseif ($text === ')') {
                $depth--;
                if ($depth === 0) {
                    break;
                }
            }
            $args[] = $t;
        }
        return $args;
    }

    private function firstTaintedVariable(array $argTokens, array $taintMap): ?string
    {
        foreach ($argTokens as $t) {
            if (is_array($t) && $t[0] === T_VARIABLE) {
                $name = $t[1];
                if (isset($taintMap[$name]) && $taintMap[$name]->tainted) {
                    return $name;
                }
            }
        }
        return null;
    }
}
