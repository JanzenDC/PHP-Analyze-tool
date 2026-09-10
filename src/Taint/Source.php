<?php
declare(strict_types=1);
namespace PHPSec\Taint;
final class Source { public function __construct(public readonly string $expression, public readonly string $kind) {} }
