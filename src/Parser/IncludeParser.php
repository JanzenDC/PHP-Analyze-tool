<?php
declare(strict_types=1);

namespace PHPSec\Parser;

use PHPSec\Rules\FunctionRules;

final class IncludeParser
{
    public function detect(Statement $statement): array
    {
        foreach ($statement->tokens as $i => $token) {
            if (is_array($token) && in_array($token[0], [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true)) {
                $arg = array_slice($statement->tokens, $i + 1);
                $text = FunctionRules::tokensToString($arg);
                return ['name' => strtolower(trim($token[1])), 'tokens' => $arg, 'taintedLooking' => preg_match('/\$[A-Za-z_]/', $text) === 1];
            }
        }
        return [];
    }
}
