<?php
declare(strict_types=1);
namespace PHPSec\Taint;
final class Sanitizer { public function __construct(public readonly string $name, public readonly array $contexts) {} }
