<?php
declare(strict_types=1);
namespace PHPSec\Detectors;
final class FileUploadDetector extends AbstractDetector
{
    public function detect(string $file, array $statements, array $taintMap): array
    {
        $result = []; $all = implode("\n", array_map(static fn($s) => $s->text(), $statements));
        $hasExtensionCheck = preg_match('/pathinfo|finfo_file|mime_content_type|extension|allowed(?:Extensions|Types)/i', $all) === 1;
        if ($hasExtensionCheck) { return []; }
        foreach ($statements as $statement) {
            foreach ($this->expressions->calls($statement->tokens, $file, $statement->line) as $call) {
                if ($call->name !== 'move_uploaded_file' || !str_contains($all, '$_FILES')) { continue; }
                $result[] = $this->finding('Unsafe File Upload', 'MEDIUM', 'LOW', $file, $statement, new \PHPSec\Taint\TaintValue('$_FILES', ['uploaded file']), 'move_uploaded_file', 'Uploaded file is moved without an obvious extension or MIME allowlist.', 'An attacker may store executable or unsafe content.', 'Validate extension and content type, generate the destination name, and store outside the web root.');
            }
        }
        return $result;
    }
}
