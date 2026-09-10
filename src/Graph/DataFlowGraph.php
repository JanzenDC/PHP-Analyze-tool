<?php
declare(strict_types=1);
namespace PHPSec\Graph;
final class DataFlowGraph
{
    private array $nodes = []; private array $edges = [];
    public function addNode(GraphNode $node): void { $this->nodes[$node->id] = $node; }
    public function addEdge(GraphEdge $edge): void { $this->edges[] = $edge; }
    public function addFlow(array $flow): void
    {
        $previous = null;
        foreach ($flow as $i => $label) {
            $id = hash('sha256', (string) $label . $i);
            $this->addNode(new GraphNode($id, (string) $label, $i === 0 ? 'source' : 'flow'));
            if ($previous !== null) { $this->addEdge(new GraphEdge($previous, $id)); }
            $previous = $id;
        }
    }
    public function toArray(): array { return ['nodes' => array_map(fn($n) => $n->toArray(), array_values($this->nodes)), 'edges' => array_map(fn($e) => $e->toArray(), $this->edges)]; }
}
