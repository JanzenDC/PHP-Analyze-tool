<?php
declare(strict_types=1);

namespace PHPSec\Taint;

use PHPSec\Parser\ExpressionParser;
use PHPSec\Parser\PHPTokenizer;
use PHPSec\Rules\FunctionRules;
use PHPSec\Rules\SanitizerRules;
use PHPSec\Rules\SourceRules;

/**
 * Linear analysis only: branches, aliases and interprocedural effects are not modeled.
 */
final class TaintEngine
{
    private SourceRules $sources;
    private SanitizerRules $sanitizers;
    private ExpressionParser $expressions;

    public function __construct()
    {
        $this->sources = new SourceRules();
        $this->sanitizers = new SanitizerRules();
        $this->expressions = new ExpressionParser();
    }

    public function analyze(array $statements): array
    {
        $map = [];
        foreach ($statements as $statement) {
            $tokens = PHPTokenizer::significant($statement->tokens);
            $equals = $this->assignmentIndex($tokens);
            if ($equals === null || !isset($tokens[0]) || !is_array($tokens[0]) || $tokens[0][0] !== T_VARIABLE) { continue; }
            $target = $tokens[0][1];
            $value = $this->taintForTokens(array_slice($tokens, $equals + 1), $map);
            if ($value === null) { unset($map[$target]); }
            else { $map[$target] = $value->through("assigned to {$target} at line {$statement->line}"); }
        }
        return $map;
    }

    public function taintForTokens(array $tokens, array $map): ?TaintValue
    {
        $text = FunctionRules::tokensToString($tokens);
        if ($this->sources->isSourceText($text)) {
            $source = $this->firstSource($text);
            $value = new TaintValue($source, ["source {$source}"]);
        } else {
            $values = [];
            foreach ($this->expressions->variables($tokens) as $variable) { if (isset($map[$variable])) { $values[] = $map[$variable]; } }
            $value = PropagationRule::merge($values, 'expression propagation');
        }
        if ($value === null) { return null; }
        $cast = $this->expressions->cast($tokens);
        if (in_array($cast, ['int', 'integer', 'float', 'double', 'bool', 'boolean'], true)) { $value = $value->through("cast to {$cast}", ['sql', 'int']); }
        foreach ($this->expressions->calls($tokens) as $call) {
            if (!$this->sanitizers->isSanitizer($call->name)) { continue; }
            $contexts = $call->name === 'basename' ? ['path-partial'] : $this->sanitizers->contexts($call->name);
            $value = $value->through("sanitized by {$call->name}", $contexts);
        }
        return $value;
    }

    private function assignmentIndex(array $tokens): ?int
    {
        $depth = 0;
        foreach ($tokens as $i => $token) {
            $text = FunctionRules::tokenText($token);
            if (in_array($text, ['(', '[', '{'], true)) { $depth++; }
            if (in_array($text, [')', ']', '}'], true)) { $depth--; }
            if ($depth === 0 && $text === '=') { return $i; }
        }
        return null;
    }

    private function firstSource(string $text): string
    {
        if (preg_match('/(\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV))\s*\[\s*(?:[\'"]([^\'"]+)[\'"]|([a-zA-Z_][a-zA-Z0-9_]*))\s*\]/', $text, $m)) {
            $key = ($m[2] ?? '') !== '' ? $m[2] : ($m[3] ?? '');
            return $key !== '' ? "{$m[1]}['{$key}']" : $m[1];
        }
        foreach ($this->sources->superglobals() as $source) {
            if (str_contains($text, $source)) {
                return $source;
            }
        }
        if (str_contains($text, 'php://input')) {
            return 'php://input';
        }
        return 'user-input';
    }
}
