<?php
declare(strict_types=1);
namespace PHPSec\AST;
final class StringNode extends Node { public function __construct(string $file, int $line, public readonly string $value) { parent::__construct($file, $line); } }
