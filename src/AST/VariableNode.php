<?php
declare(strict_types=1);
namespace PHPSec\AST;
final class VariableNode extends Node { public function __construct(string $file, int $line, public readonly string $name) { parent::__construct($file, $line); } }
