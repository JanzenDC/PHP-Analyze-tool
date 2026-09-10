<?php
declare(strict_types=1);

return [
    'sql' => ['mysqli_query', 'mysqli_multi_query', 'query', 'exec'],
    'xss' => ['echo', 'print', 'print_r', 'var_dump'],
    'command' => ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen'],
    'path' => ['file_get_contents', 'file_put_contents', 'fopen', 'readfile', 'unlink', 'rename', 'copy'],
    'include' => ['include', 'include_once', 'require', 'require_once'],
    'ssrf' => ['curl_init', 'curl_setopt', 'curl_exec', 'file_get_contents'],
    'dangerous' => ['eval', 'assert', 'create_function', 'unserialize', 'extract', 'parse_str'],
    'upload' => ['move_uploaded_file'],
];
