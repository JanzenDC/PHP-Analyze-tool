<?php
declare(strict_types=1);

return [
    'superglobals' => ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES', '$_ENV'],
    'functions' => ['file_get_contents' => ['literal' => 'php://input']],
];
