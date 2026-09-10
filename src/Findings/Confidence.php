<?php
declare(strict_types=1);

namespace PHPSec\Findings;

final class Confidence
{
    public const HIGH = 'HIGH';
    public const MEDIUM = 'MEDIUM';
    public const LOW = 'LOW';

    public static function rank(string $confidence): int
    {
        return match (strtoupper($confidence)) {
            self::HIGH => 3, self::MEDIUM => 2, self::LOW => 1, default => 0,
        };
    }
}
