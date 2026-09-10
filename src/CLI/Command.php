<?php
declare(strict_types=1);

namespace PHPSec\CLI;

abstract class Command
{
    public const CACHE_FILE = 'phpsec-last-scan.json';

    abstract public function name(): string;
    abstract public function description(): string;
    abstract public function usage(): string;

    /** @param string[] $arguments */
    abstract public function execute(array $arguments, bool $quiet = false, bool $color = true): int;

    protected function cachePath(): string
    {
        return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . self::CACHE_FILE;
    }

    protected function loadCache(): ?array
    {
        $json = @file_get_contents($this->cachePath());
        if ($json === false) {
            return null;
        }
        $data = json_decode($json, true);
        return is_array($data) ? $data : null;
    }

    protected function error(string $message): int
    {
        fwrite(STDERR, "PHPSEC: {$message}\n");
        return 1;
    }
}
