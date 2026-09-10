<?php
declare(strict_types=1);
namespace PHPSec\Scanner;
final class ExclusionManager
{
    public function __construct(private readonly array $patterns) {}
    public function isExcluded(string $path, string $root): bool
    {
        $relative = str_replace('\\', '/', ltrim(substr($path, strlen(rtrim($root, '/\\'))), '/\\'));
        foreach ($this->patterns as $pattern) {
            $pattern = str_replace('\\', '/', trim((string) $pattern, '/\\'));
            if ($relative === $pattern || str_starts_with($relative, $pattern . '/') || fnmatch($pattern, $relative, FNM_PATHNAME)) { return true; }
        }
        return false;
    }
}
