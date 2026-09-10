<?php
declare(strict_types=1);

namespace PHPSec\Taint;

/**
 * Documents the linear propagation model: taint moves through assignment,
 * concatenation and interpolation. Sanitizers clear only named contexts.
 * Branches, aliases, references and interprocedural flows are not modeled.
 */
final class PropagationRule
{
    public static function merge(array $values, string $step): ?TaintValue
    {
        if ($values === []) { return null; }
        $first = reset($values);
        $cleared = $first->contextsCleared;
        foreach ($values as $value) { $cleared = array_values(array_intersect($cleared, $value->contextsCleared)); }
        return new TaintValue($first->sourceExpr, [...$first->flow, $step], $cleared);
    }
}
