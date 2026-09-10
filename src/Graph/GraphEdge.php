<?php
declare(strict_types=1);
namespace PHPSec\Graph;
final class GraphEdge { public function __construct(public readonly string $from, public readonly string $to, public readonly string $kind = 'flows_to') {} public function toArray(): array { return get_object_vars($this); } }
