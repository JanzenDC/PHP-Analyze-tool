<?php
declare(strict_types=1);

namespace PHPSec\Parser;

final class PHPTokenizer
{
    public function tokenize(string $code): array { return token_get_all($code, TOKEN_PARSE); }
    public static function isIgnorable(array|string $token): bool
    {
        return is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_CLOSE_TAG], true);
    }
    public static function significant(array $tokens): array { return array_values(array_filter($tokens, static fn($t) => !self::isIgnorable($t))); }
}
