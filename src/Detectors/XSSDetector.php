<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class XSSDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $findings = $this->scanCalls($file, $statements, $taintMap, ['print_r', 'var_dump'], 'html', 'Cross-Site Scripting', 'MEDIUM', 'Tainted input is rendered without HTML-context encoding.', 'Attacker-controlled script may run in a user browser.', 'Encode output with htmlspecialchars using ENT_QUOTES and the correct charset.');
        foreach ($statements as $statement) {
            $tokens = \PHPSec\Parser\PHPTokenizer::significant($statement->tokens);
            foreach ($tokens as $i => $token) {
                if (!(is_array($token) && in_array($token[0], [T_ECHO, T_PRINT, T_OPEN_TAG_WITH_ECHO], true))) { continue; }
                $value = $this->value(array_slice($tokens, $i + 1), $taintMap);
                if ($value !== null && $value->isTaintedFor('html')) {
                    $findings[] = $this->finding('Cross-Site Scripting', 'MEDIUM', 'HIGH', $file, $statement, $value, strtolower(trim($token[1])), 'Tainted input is rendered without HTML-context encoding.', 'Attacker-controlled script may run in a user browser.', 'Encode output with htmlspecialchars using ENT_QUOTES and the correct charset.');
                }
            }
        }
        return $findings;
    }
}
