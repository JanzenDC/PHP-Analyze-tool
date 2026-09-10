<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class WeakSecurityDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $result = [];
        foreach ($statements as $statement) {
            $text = $statement->text();
            if (preg_match('/\b(md5|sha1)\s*\([^;]*(?:pass|password|passwd)/i', $text, $m)) {
                $result[] = $this->finding('Weak Password Hash', 'LOW', 'MEDIUM', $file, $statement, null, strtolower($m[1]), 'A fast hash appears to be used for password data.', 'Fast hashes make offline password cracking inexpensive.', 'Use password_hash() and password_verify().');
            }
            if (preg_match('/catch\s*\([^)]*\)\s*\{\s*\}/s', $text)) {
                $result[] = $this->finding('Empty Catch Block', 'INFO', 'LOW', $file, $statement, null, 'catch', 'An exception is silently discarded.', 'Security failures or operational errors may go unnoticed.', 'Handle, log, or explicitly document the ignored exception.');
            }
        }
        return $result;
    }
}
