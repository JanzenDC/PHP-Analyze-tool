<?php

namespace PHPSec\Taint;

use PHPSec\Parser\Statement;

/**
 * Propagates taint through a flat list of Statements (assignments,
 * concatenation, and simple sanitizer calls).
 *
 * V1 model:
 *  - Superglobal reads ($_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER,
 *    $_FILES, $_ENV) are SOURCES.
 *  - A short list of well-known functions/casts are SANITIZERS: if a
 *    tainted value passes through one, it is considered clean from
 *    that point on.
 *  - Taint is propagated on direct assignment (`$a = $b;`), string
 *    interpolation (`"...$b..."`), and concatenation (`$a . $b`),
 *    because token_get_all() emits interpolated/concatenated
 *    variables as their own T_VARIABLE tokens regardless of context.
 *  - Statements are processed strictly in file order. Branches
 *    (if/else, loops) are NOT modeled separately -- every statement is
 *    assumed to execute. This can produce false positives/negatives
 *    across conditional sanitization and is a documented V1 limitation.
 */
class TaintEngine
{
    public const SOURCES = [
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES', '$_ENV',
    ];

    public const SANITIZER_FUNCTIONS = [
        'intval', 'floatval', 'boolval',
        'mysqli_real_escape_string',
        'htmlspecialchars', 'htmlentities',
        'addslashes',
        'preg_quote',
        'basename', // common (imperfect) path-traversal mitigation
    ];

    public const CAST_TOKEN_TYPES = [
        T_INT_CAST, T_DOUBLE_CAST, T_BOOL_CAST,
    ];

    /** @var array<string, TaintInfo> */
    private array $taintMap = [];

    /**
     * @param Statement[] $statements
     * @return array<string, TaintInfo>
     */
    public function analyze(array $statements): array
    {
        $this->taintMap = [];

        foreach ($statements as $stmt) {
            $this->processStatement($stmt);
        }

        return $this->taintMap;
    }

    /** Read-only accessor for a detector that needs the map after analyze() */
    public function getTaintMap(): array
    {
        return $this->taintMap;
    }

    private function processStatement(Statement $stmt): void
    {
        $tokens = $stmt->tokens;
        $assignIndex = $this->findTopLevelAssignment($tokens);

        if ($assignIndex === null) {
            return; // Not a simple assignment; detectors handle calls/sinks separately.
        }

        $lhsToken = $tokens[0] ?? null;
        if (!is_array($lhsToken) || $lhsToken[0] !== T_VARIABLE) {
            return; // e.g. list($a, $b) = ... ; not modeled in V1.
        }
        $lhsVar = $lhsToken[1];

        $rhsTokens = array_slice($tokens, $assignIndex + 1);
        $result = $this->evaluateRhsTaint($rhsTokens, $stmt->line);

        if ($result === null) {
            // RHS has no source/tainted-variable involvement -> LHS becomes clean.
            unset($this->taintMap[$lhsVar]);
            return;
        }

        [$tainted, $flow, $sourceExpr, $sanitizers] = $result;

        if (!$tainted) {
            unset($this->taintMap[$lhsVar]);
            return;
        }

        $newFlow = $flow;
        $newFlow[] = $lhsVar;

        $info = new TaintInfo(true, $newFlow, $sourceExpr, $stmt->line);
        $info->sanitizersSeen = $sanitizers;
        $this->taintMap[$lhsVar] = $info;
    }

    /**
     * Finds the index of a plain `=` assignment token at bracket depth 0.
     * Returns null if this statement is not a simple assignment
     * (compound assignments like += are ignored in V1).
     */
    private function findTopLevelAssignment(array $tokens): ?int
    {
        $depth = 0;
        foreach ($tokens as $i => $token) {
            $text = is_array($token) ? $token[1] : $token;
            if ($text === '(' || $text === '[' || $text === '{') {
                $depth++;
            } elseif ($text === ')' || $text === ']' || $text === '}') {
                $depth--;
            } elseif ($text === '=' && $depth === 0) {
                return $i;
            }
        }
        return null;
    }

    /**
     * Walks the RHS tokens tracking sanitizer-call scope by paren depth,
     * and reports whether the expression is tainted.
     *
     * @return array{0: bool, 1: string[], 2: ?string, 3: string[]}|null
     *         [tainted, flow, sourceExpr, sanitizersSeen] or null if no
     *         source/variable was involved at all (RHS is a plain literal).
     */
    private function evaluateRhsTaint(array $tokens, int $line): ?array
    {
        $depth = 0;
        $sanitizerStack = []; // stack of ['depth' => int]
        $hasCast = false;
        $sanitizersSeen = [];

        $tainted = false;
        $flow = [];
        $sourceExpr = null;
        $anyVarOrSource = false;

        $n = count($tokens);
        for ($i = 0; $i < $n; $i++) {
            $token = $tokens[$i];
            $text = is_array($token) ? $token[1] : $token;
            $type = is_array($token) ? $token[0] : null;

            if ($type !== null && in_array($type, self::CAST_TOKEN_TYPES, true)) {
                $hasCast = true;
                $sanitizersSeen[] = trim($text);
                continue;
            }

            if ($text === '(') {
                // Was the previous meaningful token a sanitizer function name?
                $prev = $this->prevMeaningful($tokens, $i);
                $depth++;
                if ($prev !== null && is_array($prev) && $prev[0] === T_STRING
                    && in_array($prev[1], self::SANITIZER_FUNCTIONS, true)) {
                    $sanitizerStack[] = ['depth' => $depth, 'name' => $prev[1]];
                }
                continue;
            }

            if ($text === ')') {
                if (!empty($sanitizerStack) && end($sanitizerStack)['depth'] === $depth) {
                    $popped = array_pop($sanitizerStack);
                    $sanitizersSeen[] = $popped['name'];
                }
                $depth--;
                continue;
            }

            if ($type === T_VARIABLE) {
                $varName = $text;
                $insideSanitizer = !empty($sanitizerStack) || $hasCast;

                if (in_array($varName, self::SOURCES, true)) {
                    $anyVarOrSource = true;
                    $expr = $this->captureSuperglobalAccess($tokens, $i, $varName);
                    if (!$insideSanitizer) {
                        $tainted = true;
                        if ($sourceExpr === null) {
                            $sourceExpr = $expr;
                            $flow = [$expr];
                        }
                    }
                    continue;
                }

                if (isset($this->taintMap[$varName])) {
                    $anyVarOrSource = true;
                    $existing = $this->taintMap[$varName];
                    if ($existing->tainted && !$insideSanitizer) {
                        $tainted = true;
                        if ($sourceExpr === null) {
                            $sourceExpr = $existing->sourceExpr;
                            $flow = $existing->flow; // already ends with $varName
                        }
                    }
                    continue;
                }
            }
        }

        if (!$anyVarOrSource) {
            return null;
        }

        return [$tainted, $flow, $sourceExpr, array_values(array_unique($sanitizersSeen))];
    }

    /** Best-effort reconstruction of e.g. $_GET['id'] for reporting purposes. */
    private function captureSuperglobalAccess(array $tokens, int $startIndex, string $varName): string
    {
        $n = count($tokens);
        if (($startIndex + 1) >= $n) {
            return $varName;
        }
        $next = $tokens[$startIndex + 1];
        $nextText = is_array($next) ? $next[1] : $next;
        if ($nextText !== '[') {
            return $varName;
        }

        $depth = 0;
        $out = $varName;
        for ($j = $startIndex + 1; $j < $n; $j++) {
            $t = $tokens[$j];
            $tt = is_array($t) ? $t[1] : $t;
            $out .= $tt;
            if ($tt === '[') {
                $depth++;
            } elseif ($tt === ']') {
                $depth--;
                if ($depth === 0) {
                    break;
                }
            }
        }
        return $out;
    }

    private function prevMeaningful(array $tokens, int $index)
    {
        for ($j = $index - 1; $j >= 0; $j--) {
            return $tokens[$j]; // whitespace/comments already stripped by TokenWalker
        }
        return null;
    }
}
