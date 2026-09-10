#!/usr/bin/env php
<?php
declare(strict_types=1);

require __DIR__ . '/src/Autoload.php';

use PHPSec\CLI\Application;

exit((new Application())->run($argv));
