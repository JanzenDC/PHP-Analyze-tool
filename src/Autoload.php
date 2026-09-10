<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'PHPSec\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $file = __DIR__ . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
