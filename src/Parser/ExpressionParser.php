<?php
declare(strict_types=1);

namespace PHPSec\Parser;

use PHPSec\Rules\FunctionRules;

final class ExpressionParser
{
    public function variables(array $tokens): array
    {
        $vars = [];
        foreach ($tokens as $token) {
            if (is_array($token) && $token[0] === T_VARIABLE) { $vars[] = $token[1]; }
            if (is_array($token) && $token[0] === T_ENCAPSED_AND_WHITESPACE
                && preg_match_all('/\$[A-Za-z_][A-Za-z0-9_]*/', $token[1], $matches)) { $vars = [...$vars, ...$matches[0]]; }
        }
        return array_values(array_unique($vars));
    }

    public function hasConcatenation(array $tokens): bool { return in_array('.', $tokens, true); }
    public function hasInterpolation(array $tokens): bool
    {
        foreach ($tokens as $token) { if (is_array($token) && in_array($token[0], [T_ENCAPSED_AND_WHITESPACE, T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true)) { return true; } }
        return false;
    }

    public function calls(array $tokens, string $file = '', int $line = 1): array
    {
        $calls = []; $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_STRING) { continue; }
            $j = $i + 1; while ($j < $count && PHPTokenizer::isIgnorable($tokens[$j])) { $j++; }
            if (($tokens[$j] ?? null) !== '(') { continue; }
            $prev = $i - 1; while ($prev >= 0 && PHPTokenizer::isIgnorable($tokens[$prev])) { $prev--; }
            $isMethod = $prev >= 0 && ((is_array($tokens[$prev]) && $tokens[$prev][0] === T_OBJECT_OPERATOR) || $tokens[$prev] === '::');
            [$args, $end] = $this->arguments($tokens, $j);
            $calls[] = new \PHPSec\AST\FunctionCallNode($file, is_array($tokens[$i]) ? $tokens[$i][2] : $line, strtolower($tokens[$i][1]), $args, $isMethod, $isMethod ? strtolower($tokens[$i][1]) : null);
            $i = $end;
        }
        return $calls;
    }

    private function arguments(array $tokens, int $open): array
    {
        $args = []; $arg = []; $depth = 0; $i = $open + 1;
        for (; $i < count($tokens); $i++) {
            $text = FunctionRules::tokenText($tokens[$i]);
            if ($text === '(' || $text === '[') { $depth++; }
            if ($text === ')' && $depth === 0) { if ($arg !== []) { $args[] = $arg; } break; }
            if (($text === ')' || $text === ']') && $depth > 0) { $depth--; }
            if ($text === ',' && $depth === 0) { $args[] = $arg; $arg = []; } else { $arg[] = $tokens[$i]; }
        }
        return [$args, $i];
    }

    public function cast(array $tokens): ?string
    {
        foreach ($tokens as $token) {
            if (is_array($token) && in_array($token[0], [T_INT_CAST, T_DOUBLE_CAST, T_STRING_CAST, T_BOOL_CAST, T_ARRAY_CAST], true)) { return strtolower(trim($token[1], " \t\n\r\0\x0B()")); }
        }
        return null;
    }
}
