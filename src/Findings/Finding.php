<?php
declare(strict_types=1);

namespace PHPSec\Findings;

final class Finding
{
    public function __construct(
        public string $id,
        public readonly string $type,
        public readonly string $severity,
        public readonly string $confidence,
        public readonly string $file,
        public readonly int $line,
        public readonly ?string $source,
        public readonly string $sink,
        public readonly array $flow,
        public readonly string $description,
        public readonly string $impact,
        public readonly string $recommendation,
        public readonly array $codeContext = [],
    ) {}

    public function toArray(): array
    {
        return get_object_vars($this);
    }
}
