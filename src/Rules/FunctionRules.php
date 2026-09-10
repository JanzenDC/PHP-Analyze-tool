<?php
declare(strict_types=1);

namespace PHPSec\Rules;

final class FunctionRules
{
    public static function normalize(string $name): string { return strtolower(ltrim($name, '\\')); }
    public static function isAny(string $name, array $candidates): bool
    {
        return in_array(self::normalize($name), array_map([self::class, 'normalize'], $candidates), true);
    }
    public static function tokenText(array|string $token): string { return is_array($token) ? $token[1] : $token; }
    public static function tokensToString(array $tokens): string
    {
        return implode('', array_map([self::class, 'tokenText'], $tokens));
    }
}
