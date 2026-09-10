<?php
declare(strict_types=1);
namespace PHPSec\Graph;
final class GraphNode { public function __construct(public readonly string $id, public readonly string $label, public readonly string $kind, public readonly ?string $file = null, public readonly ?int $line = null) {} public function toArray(): array { return get_object_vars($this); } }
