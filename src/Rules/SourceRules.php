<?php
declare(strict_types=1);

namespace PHPSec\Rules;

final class SourceRules
{
    private array $rules;
    public function __construct(?string $file = null) { $this->rules = require ($file ?? dirname(__DIR__, 2) . '/rules/sources.php'); }
    public function superglobals(): array { return $this->rules['superglobals']; }
    public function isSourceText(string $text): bool
    {
        foreach ($this->superglobals() as $source) { if (str_contains($text, $source)) { return true; } }
        return preg_match('/file_get_contents\s*\(\s*[\'"]php:\/\/input[\'"]\s*\)/i', $text) === 1;
    }
}
