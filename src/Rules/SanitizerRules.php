<?php
declare(strict_types=1);

namespace PHPSec\Rules;

final class SanitizerRules
{
    private array $rules;
    public function __construct(?string $file = null) { $this->rules = require ($file ?? dirname(__DIR__, 2) . '/rules/sanitizers.php'); }
    public function contexts(string $function): array { return $this->rules[strtolower($function)] ?? []; }
    public function isSanitizer(string $function): bool { return isset($this->rules[strtolower($function)]); }
    public function all(): array { return $this->rules; }
}
