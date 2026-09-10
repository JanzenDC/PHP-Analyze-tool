<?php
declare(strict_types=1);
namespace PHPSec\Scanner;
final class FileScanResult
{
    public function __construct(public readonly string $file, public readonly array $findings, public readonly array $stats) {}
    public function toArray(): array { return ['file' => $this->file, 'findings' => array_map(fn($f) => $f->toArray(), $this->findings), 'stats' => $this->stats]; }
}
