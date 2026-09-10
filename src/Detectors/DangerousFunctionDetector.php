<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class DangerousFunctionDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $result = [];
        foreach ($statements as $statement) {
            foreach ($this->expressions->calls($statement->tokens, $file, $statement->line) as $call) {
                if (!in_array($call->name, ['eval', 'assert', 'create_function', 'unserialize', 'extract', 'parse_str'], true)) { continue; }
                $value = null; foreach ($call->args as $arg) { $value = $this->value($arg, $taintMap); if ($value !== null) { break; } }
                $result[] = $this->finding('Dangerous Function Usage', $value ? 'HIGH' : 'LOW', $value ? 'HIGH' : 'MEDIUM', $file, $statement, $value, $call->name, "Use of risky PHP function {$call->name}.", 'Misuse can enable injection, object injection, or variable manipulation.', 'Replace with a narrowly scoped safe API and validate untrusted data.');
            }
            foreach ($statement->tokens as $token) {
                if (is_array($token) && $token[0] === T_EVAL) {
                    $value = $this->value($statement->tokens, $taintMap);
                    $result[] = $this->finding('Dangerous Function Usage', $value ? 'HIGH' : 'LOW', $value ? 'HIGH' : 'MEDIUM', $file, $statement, $value, 'eval', 'Use of risky PHP function eval.', 'Injected PHP code may execute.', 'Remove dynamic code evaluation.');
                    break;
                }
            }
        }
        return $result;
    }
}
