<?php
declare(strict_types=1);

namespace PHPSec\Parser;

final class StatementParser
{
    public function parseFile(string $file): array { return $this->parse((string) file_get_contents($file), $file); }

    /** @return Statement[] */
    public function parse(string $code, string $file = ''): array
    {
        $tokens = (new PHPTokenizer())->tokenize($code);
        $result = []; $current = []; $line = 1; $start = 1; $depth = 0;
        foreach ($tokens as $token) {
            $text = is_array($token) ? $token[1] : $token;
            if ($current === [] && !PHPTokenizer::isIgnorable($token)) { $start = is_array($token) ? $token[2] : $line; }
            $current[] = $token;
            if ($text === '(' || $text === '[') { $depth++; }
            if ($text === ')' || $text === ']') { $depth--; }
            $boundary = ($text === ';' && $depth === 0)
                || ($depth === 0 && is_array($token) && in_array($token[0], [T_OPEN_TAG_WITH_ECHO, T_CLOSE_TAG], true));
            if ($boundary && PHPTokenizer::significant($current) !== []) {
                $result[] = new Statement($current, $start, $file);
                $current = [];
            }
            $line += substr_count($text, "\n");
        }
        if (PHPTokenizer::significant($current) !== []) { $result[] = new Statement($current, $start, $file); }
        return $result;
    }
}
