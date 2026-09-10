<?php
declare(strict_types=1);
namespace PHPSec\Taint;
final class Sink { public function __construct(public readonly string $name, public readonly string $category) {} }
