<?php

namespace PHPSec\Taint;

/**
 * Taint state attached to a single variable at a single point in the
 * (linear, branch-unaware) statement stream.
 */
class TaintInfo
{
    public bool $tainted;

    /** @var string[] Human-readable hop-by-hop flow, e.g. ["$_GET['id']", "$id", "$sql"] */
    public array $flow;

    public ?string $sourceExpr;
    public int $sourceLine;

    /** @var string[] Names of sanitizer functions/casts seen anywhere along the flow (informational) */
    public array $sanitizersSeen = [];

    public function __construct(bool $tainted, array $flow = [], ?string $sourceExpr = null, int $sourceLine = 0)
    {
        $this->tainted = $tainted;
        $this->flow = $flow;
        $this->sourceExpr = $sourceExpr;
        $this->sourceLine = $sourceLine;
    }
}
