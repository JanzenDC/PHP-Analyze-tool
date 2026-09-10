<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class HardcodedSecretDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $result = [];
        foreach ($statements as $statement) {
            $text = $statement->text();
            if (!preg_match('/\$(?:password|passwd|api_?key|secret|token)\w*\s*=\s*([\'"])([^\'"\r\n]{6,})\1/i', $text, $m)) { continue; }
            $secret = $m[2];
            if (!$this->looksSecret($secret)) { continue; }
            $masked = substr($secret, 0, min(3, strlen($secret))) . str_repeat('*', min(12, max(3, strlen($secret) - 3)));
            $safeStatement = new \PHPSec\Parser\Statement([], $statement->line, $file);
            $result[] = $this->finding('Hardcoded Secret', 'HIGH', 'MEDIUM', $file, $safeStatement, null, 'assignment', "A likely secret ({$masked}) is hardcoded.", 'Credentials committed to source can be exposed and reused.', 'Load secrets from environment or a secret manager and rotate this value.');
        }
        return $result;
    }
    private function looksSecret(string $value): bool
    {
        if (preg_match('/^(sk_|ghp_|AKIA|AIza|xox[baprs]-)/', $value)) { return true; }
        return strlen($value) >= 12 && count(array_unique(str_split($value))) >= 7;
    }
}
