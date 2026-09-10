<?php
declare(strict_types=1);

namespace PHPSec\Config;

use InvalidArgumentException;

final class Configuration
{
    public function __construct(
        public readonly array $exclude = ['vendor', '.git', 'node_modules'],
        public readonly string $minimumSeverity = 'INFO',
        public readonly string $minimumConfidence = 'LOW',
        public readonly array $rules = [],
        public readonly ?string $scanRoot = null,
    ) {}

    public static function load(string $projectRoot, ?string $scanTarget = null): self
    {
        $candidates = [rtrim($projectRoot, '/\\') . '/phpsec.php.json'];
        if ($scanTarget !== null) {
            $base = is_dir($scanTarget) ? $scanTarget : dirname($scanTarget);
            array_unshift($candidates, rtrim($base, '/\\') . '/phpsec.php.json');
        }
        foreach (array_unique($candidates) as $file) {
            if (!is_file($file)) {
                continue;
            }
            $data = json_decode((string) file_get_contents($file), true);
            if (!is_array($data)) {
                throw new InvalidArgumentException("Invalid configuration JSON: {$file}");
            }
            return new self(
                array_values(array_map('strval', $data['exclude'] ?? ['vendor', '.git', 'node_modules'])),
                strtoupper((string) ($data['severity']['min'] ?? $data['severity_min'] ?? 'INFO')),
                strtoupper((string) ($data['confidence']['min'] ?? $data['confidence_min'] ?? 'LOW')),
                is_array($data['rules'] ?? null) ? $data['rules'] : [],
                isset($data['scan_root']) ? (string) $data['scan_root'] : null,
            );
        }
        return new self();
    }

    public function ruleEnabled(string $name): bool
    {
        return !array_key_exists($name, $this->rules) || (bool) $this->rules[$name];
    }
}
