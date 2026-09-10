<?php
declare(strict_types=1);

namespace PHPSec\Findings;

final class Severity
{
    public const CRITICAL = 'CRITICAL';
    public const HIGH = 'HIGH';
    public const MEDIUM = 'MEDIUM';
    public const LOW = 'LOW';
    public const INFO = 'INFO';

    public static function rank(string $severity): int
    {
        return match (strtoupper($severity)) {
            self::CRITICAL => 5, self::HIGH => 4, self::MEDIUM => 3,
            self::LOW => 2, self::INFO => 1, default => 0,
        };
    }
}
