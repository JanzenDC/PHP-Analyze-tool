<?php
declare(strict_types=1);

namespace PHPSec\Rules;

final class SinkRules
{
    private array $rules;
    public function __construct(?string $file = null) { $this->rules = require ($file ?? dirname(__DIR__, 2) . '/rules/sinks.php'); }
    public function category(string $name): ?string
    {
        $name = strtolower($name);
        foreach ($this->rules as $category => $names) { if (in_array($name, $names, true)) { return $category; } }
        return null;
    }
    public function all(): array { return $this->rules; }
}
