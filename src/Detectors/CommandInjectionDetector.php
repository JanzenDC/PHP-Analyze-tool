<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class CommandInjectionDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        return $this->scanCalls($file, $statements, $taintMap, ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen'], 'cmd', 'Command Injection', 'HIGH', 'Tainted input reaches an operating-system command.', 'Arbitrary commands may execute with the PHP process privileges.', 'Avoid shell execution or strictly allowlist arguments.');
    }
}
