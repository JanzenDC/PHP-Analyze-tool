<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
use PHPSec\Parser\IncludeParser;
final class FileInclusionDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $result = []; $parser = new IncludeParser();
        foreach ($statements as $statement) {
            $include = $parser->detect($statement);
            if ($include === []) { continue; }
            $value = $this->value($include['tokens'], $taintMap);
            if ($value !== null && $value->isTaintedFor('path')) {
                $result[] = $this->finding('File Inclusion', 'HIGH', 'HIGH', $file, $statement, $value, $include['name'], 'Tainted input controls an included PHP path.', 'Local or remote code may be loaded into the application.', 'Use a fixed allowlist mapping identifiers to known files.');
            }
        }
        return $result;
    }
}
