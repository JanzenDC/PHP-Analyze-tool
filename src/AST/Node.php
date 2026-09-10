<?php
declare(strict_types=1);

namespace PHPSec\AST;

abstract class Node
{
    public function __construct(public readonly string $file, public readonly int $line) {}
}
