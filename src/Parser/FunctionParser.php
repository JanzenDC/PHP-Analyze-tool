<?php
declare(strict_types=1);

namespace PHPSec\Parser;

final class FunctionParser
{
    public function declarations(array $tokens): array
    {
        $result = [];
        foreach ($tokens as $i => $token) {
            if (!is_array($token) || $token[0] !== T_FUNCTION) { continue; }
            for ($j = $i + 1; $j < count($tokens); $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $result[] = ['name' => $tokens[$j][1], 'line' => $token[2]];
                    break;
                }
                if ($tokens[$j] === '(') { break; }
            }
        }
        return $result;
    }
}
