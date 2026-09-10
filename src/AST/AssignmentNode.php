<?php
declare(strict_types=1);
namespace PHPSec\AST;
final class AssignmentNode extends Node { public function __construct(string $file, int $line, public readonly string $target, public readonly array $rhs) { parent::__construct($file, $line); } }
