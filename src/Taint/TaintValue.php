<?php
declare(strict_types=1);

namespace PHPSec\Taint;

final class TaintValue
{
    public function __construct(
        public readonly string $sourceExpr,
        public readonly array $flow = [],
        public readonly array $contextsCleared = [],
    ) {}

    public function isTaintedFor(string $context): bool
    {
        return !in_array(strtolower($context), array_map('strtolower', $this->contextsCleared), true);
    }

    public function through(string $step, array $cleared = []): self
    {
        return new self($this->sourceExpr, [...$this->flow, $step], array_values(array_unique([...$this->contextsCleared, ...$cleared])));
    }
}
