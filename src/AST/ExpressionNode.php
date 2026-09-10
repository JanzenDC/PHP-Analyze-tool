<?php
declare(strict_types=1);
namespace PHPSec\AST;
final class ExpressionNode extends Node { public function __construct(string $file, int $line, public readonly array $tokens) { parent::__construct($file, $line); } }
