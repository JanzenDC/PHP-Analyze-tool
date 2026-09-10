<?php

namespace PHPSec\Parser;

/**
 * A single PHP statement, represented as its raw token list plus
 * some convenience metadata (line number, source text).
 */
class Statement
{
    /** @var array Raw tokens as returned by token_get_all() for this statement (excluding the trailing ';') */
    public array $tokens;
    public int $line;
    public string $text;

    public function __construct(array $tokens, int $line, string $text)
    {
        $this->tokens = $tokens;
        $this->line = $line;
        $this->text = trim($text);
    }
}

/**
 * Walks token_get_all() output and groups tokens into top-level
 * statements (split on ';' at brace-depth 0).
 *
 * This is intentionally NOT a full AST. V1 only needs enough structure
 * to see "assignment" and "call" shapes on a single line/statement.
 * Control flow (if/for/while bodies) is walked too, but branches are
 * NOT modeled separately -- every statement is treated as if it always
 * executes, in file order. That is a known, documented limitation (see
 * README "V1 limitations").
 */
class TokenWalker
{
    public function parseFile(string $path): array
    {
        $code = file_get_contents($path);
        if ($code === false) {
            throw new \RuntimeException("Could not read file: $path");
        }
        return $this->parseSource($code);
    }

    /**
     * @return Statement[]
     */
    public function parseSource(string $code): array
    {
        $tokens = token_get_all($code);

        $statements = [];
        $current = [];
        $depth = 0; // brace/paren/bracket depth so we don't split ';' inside for(;;) etc.
        $startLine = null;

        foreach ($tokens as $token) {
            $line = is_array($token) ? $token[2] : null;
            $text = is_array($token) ? $token[1] : $token;

            if ($startLine === null && $line !== null) {
                $startLine = $line;
            }

            // Track nesting so we only split on top-level ';'
            if ($text === '(' || $text === '{' || $text === '[') {
                $depth++;
            } elseif ($text === ')' || $text === '}' || $text === ']') {
                $depth--;
            }

            if ($text === ';' && $depth <= 0) {
                if (!empty($current)) {
                    $statements[] = new Statement(
                        $current,
                        $startLine ?? 0,
                        $this->stringifyTokens($current)
                    );
                }
                $current = [];
                $startLine = null;
                continue;
            }

            // Skip pure whitespace/comment/tag noise but keep it out of $current.
            // T_OPEN_TAG in particular must not leak into the next statement's
            // token list, or a leading "<?php\n$x = ...;" would make the
            // statement start with a tag token instead of T_VARIABLE.
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_CLOSE_TAG], true)) {
                continue;
            }

            $current[] = $token;
        }

        // Trailing statement without a terminating ';' (rare, but be safe)
        if (!empty($current)) {
            $statements[] = new Statement($current, $startLine ?? 0, $this->stringifyTokens($current));
        }

        return $statements;
    }

    private function stringifyTokens(array $tokens): string
    {
        $out = '';
        foreach ($tokens as $t) {
            $out .= is_array($t) ? $t[1] : $t;
        }
        return $out;
    }
}
