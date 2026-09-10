<?php
declare(strict_types=1);

namespace PHPSec\Detectors;

interface DetectorInterface
{
    /** @return \PHPSec\Findings\Finding[] */
    public function detect(string $file, array $statements, array $taintMap): array;
}
