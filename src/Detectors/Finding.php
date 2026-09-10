<?php

namespace PHPSec\Detectors;

class Finding
{
    public string $id;
    public string $type;
    public string $severity;
    public string $confidence;
    public string $file;
    public int $line;
    public ?string $source;
    public string $sink;
    /** @var string[] */
    public array $flow;
    public string $reason;
    public string $recommendation;

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'severity' => $this->severity,
            'confidence' => $this->confidence,
            'file' => $this->file,
            'line' => $this->line,
            'source' => $this->source,
            'sink' => $this->sink,
            'flow' => $this->flow,
            'reason' => $this->reason,
            'recommendation' => $this->recommendation,
        ];
    }
}
