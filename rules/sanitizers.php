<?php
declare(strict_types=1);

return [
    'htmlspecialchars' => ['html'], 'htmlentities' => ['html'],
    'mysqli_real_escape_string' => ['sql'], 'pg_escape_string' => ['sql'],
    'intval' => ['sql', 'int'], 'filter_var' => ['int'],
    'escapeshellarg' => ['cmd'], 'escapeshellcmd' => ['cmd'],
    'basename' => ['path'], 'realpath' => ['path'],
    'urlencode' => ['url'], 'rawurlencode' => ['url'],
];
