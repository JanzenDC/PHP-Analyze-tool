<?php
declare(strict_types=1);
namespace PHPSec\AST;
final class FunctionCallNode extends Node
{
    public function __construct(string $file, int $line, public readonly string $name, public readonly array $args, public readonly bool $isMethod = false, public readonly ?string $methodName = null) { parent::__construct($file, $line); }
}
