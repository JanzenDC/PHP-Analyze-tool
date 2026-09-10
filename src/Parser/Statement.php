<?php
declare(strict_types=1);

namespace PHPSec\Parser;

use PHPSec\Rules\FunctionRules;

final class Statement
{
    public function __construct(public readonly array $tokens, public readonly int $line, public readonly string $file = '') {}
    public function text(): string { return FunctionRules::tokensToString($this->tokens); }
}
