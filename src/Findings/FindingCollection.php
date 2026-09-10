<?php
declare(strict_types=1);

namespace PHPSec\Findings;

use Countable;
use IteratorAggregate;
use ArrayIterator;
use Traversable;

final class FindingCollection implements Countable, IteratorAggregate
{
    /** @var Finding[] */
    private array $items = [];

    public function add(Finding $finding): void { $this->items[] = $finding; }
    public function all(): array { return $this->items; }
    public function count(): int { return count($this->items); }
    public function getIterator(): Traversable { return new ArrayIterator($this->items); }

    public function filter(string $minimumSeverity = 'INFO', string $minimumConfidence = 'LOW'): self
    {
        $result = new self();
        foreach ($this->items as $item) {
            if (Severity::rank($item->severity) >= Severity::rank($minimumSeverity)
                && Confidence::rank($item->confidence) >= Confidence::rank($minimumConfidence)) {
                $result->add($item);
            }
        }
        return $result;
    }

    public function countBySeverity(): array
    {
        $counts = array_fill_keys([Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM, Severity::LOW, Severity::INFO], 0);
        foreach ($this->items as $item) { $counts[$item->severity] = ($counts[$item->severity] ?? 0) + 1; }
        return $counts;
    }

    public function getById(string $id): ?Finding
    {
        foreach ($this->items as $item) { if ($item->id === $id) { return $item; } }
        return null;
    }
}
