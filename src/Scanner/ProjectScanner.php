<?php
declare(strict_types=1);

namespace PHPSec\Scanner;

use PHPSec\Findings\FindingCollection;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use FilesystemIterator;

final class ProjectScanner
{
    public function __construct(private readonly FileScanner $fileScanner, private readonly ExclusionManager $exclusions) {}

    public function scan(string $target): ScanResult
    {
        $start = microtime(true); $files = [];
        if (is_file($target)) { $files[] = $target; $root = dirname($target); }
        else {
            $root = realpath($target) ?: $target;
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $item) {
                $path = $item->getPathname();
                if ($item->isFile() && strtolower($item->getExtension()) === 'php' && !$this->exclusions->isExcluded($path, $root)) { $files[] = $path; }
            }
        }
        sort($files);
        $collection = new FindingCollection();
        $stats = ['files' => 0, 'statements' => 0, 'sources' => 0, 'sinks' => 0, 'functions' => 0];
        $id = 1;
        foreach ($files as $file) {
            $result = $this->fileScanner->scan($file); $stats['files']++;
            foreach (['statements', 'sources', 'sinks', 'functions'] as $key) { $stats[$key] += $result->stats[$key]; }
            foreach ($result->findings as $finding) { $finding->id = sprintf('PHPSEC-%03d', $id++); $collection->add($finding); }
        }
        return new ScanResult($collection, $stats, microtime(true) - $start);
    }
}
