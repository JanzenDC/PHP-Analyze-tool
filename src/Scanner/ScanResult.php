<?php
declare(strict_types=1);
namespace PHPSec\Scanner;
use PHPSec\Findings\FindingCollection;
final class ScanResult
{
    public function __construct(public readonly FindingCollection $findings, public readonly array $stats, public readonly float $durationSeconds) {}
    public function toArray(): array { return ['findings' => array_map(fn($f) => $f->toArray(), $this->findings->all()), 'stats' => $this->stats, 'duration_seconds' => $this->durationSeconds]; }
}
