<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class SSRFDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        return $this->scanCalls($file, $statements, $taintMap, ['curl_init', 'curl_setopt', 'curl_exec', 'file_get_contents'], 'url', 'Server-Side Request Forgery', 'MEDIUM', 'Tainted input may control an outbound URL.', 'An attacker may reach internal or metadata services.', 'Allowlist schemes and destinations; block private and link-local networks.');
    }
}
