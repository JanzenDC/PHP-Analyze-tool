<?php
declare(strict_types=1);

namespace PHPSec\Scanner;

use PHPSec\Detectors\DetectorInterface;
use PHPSec\Parser\FunctionParser;
use PHPSec\Parser\StatementParser;
use PHPSec\Rules\SinkRules;
use PHPSec\Rules\SourceRules;
use PHPSec\Taint\TaintEngine;

final class FileScanner
{
    /** @param DetectorInterface[] $detectors */
    public function __construct(private readonly array $detectors) {}

    public function scan(string $file): FileScanResult
    {
        $code = (string) file_get_contents($file);
        $statements = (new StatementParser())->parse($code, $file);
        $taintMap = (new TaintEngine())->analyze($statements);
        $findings = [];
        foreach ($this->detectors as $detector) { $findings = [...$findings, ...$detector->detect($file, $statements, $taintMap)]; }
        $tokens = token_get_all($code);
        $sourceRules = new SourceRules(); $sinkRules = new SinkRules();
        $sources = 0; foreach ($sourceRules->superglobals() as $source) { $sources += substr_count($code, $source); }
        $sinks = 0; foreach ($sinkRules->all() as $names) { foreach ($names as $name) { $sinks += preg_match_all('/\b' . preg_quote($name, '/') . '\s*\(/i', $code); } }
        return new FileScanResult($file, $findings, [
            'statements' => count($statements),
            'sources' => $sources,
            'sinks' => $sinks,
            'functions' => count((new FunctionParser())->declarations($tokens)),
        ]);
    }
}
