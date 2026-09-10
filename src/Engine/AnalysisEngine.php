<?php
declare(strict_types=1);

namespace PHPSec\Engine;

use PHPSec\Config\Configuration;
use PHPSec\Detectors\CommandInjectionDetector;
use PHPSec\Detectors\DangerousFunctionDetector;
use PHPSec\Detectors\FileInclusionDetector;
use PHPSec\Detectors\FileUploadDetector;
use PHPSec\Detectors\HardcodedSecretDetector;
use PHPSec\Detectors\PathTraversalDetector;
use PHPSec\Detectors\SQLInjectionDetector;
use PHPSec\Detectors\SSRFDetector;
use PHPSec\Detectors\WeakSecurityDetector;
use PHPSec\Detectors\XSSDetector;
use PHPSec\Scanner\ExclusionManager;
use PHPSec\Scanner\FileScanner;
use PHPSec\Scanner\ProjectScanner;
use PHPSec\Scanner\ScanResult;

final class AnalysisEngine
{
    public function __construct(private readonly Configuration $configuration = new Configuration()) {}

    public function scan(string $target): ScanResult
    {
        if ($this->configuration->scanRoot !== null && is_dir($target)) {
            $target = rtrim($target, '/\\') . DIRECTORY_SEPARATOR . ltrim($this->configuration->scanRoot, '/\\');
        }
        $classes = [
            'sql_injection' => SQLInjectionDetector::class,
            'xss' => XSSDetector::class,
            'command_injection' => CommandInjectionDetector::class,
            'path_traversal' => PathTraversalDetector::class,
            'file_inclusion' => FileInclusionDetector::class,
            'ssrf' => SSRFDetector::class,
            'file_upload' => FileUploadDetector::class,
            'dangerous_functions' => DangerousFunctionDetector::class,
            'hardcoded_secrets' => HardcodedSecretDetector::class,
            'weak_security' => WeakSecurityDetector::class,
        ];
        $detectors = [];
        foreach ($classes as $name => $class) { if ($this->configuration->ruleEnabled($name)) { $detectors[] = new $class(); } }
        $scanner = new ProjectScanner(new FileScanner($detectors), new ExclusionManager($this->configuration->exclude));
        $result = $scanner->scan($target);
        return new ScanResult($result->findings->filter($this->configuration->minimumSeverity, $this->configuration->minimumConfidence), $result->stats, $result->durationSeconds);
    }
}
