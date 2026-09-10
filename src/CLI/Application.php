<?php
declare(strict_types=1);

namespace PHPSec\CLI;

final class Application
{
    /** @var array<string, Command> */
    private array $commands = [];

    public function __construct()
    {
        foreach ([new ScanCommand(), new FindingsCommand(), new FlowCommand(), new StatsCommand()] as $command) {
            $this->commands[$command->name()] = $command;
        }
    }

    /** @param string[] $argv */
    public function run(array $argv): int
    {
        array_shift($argv);
        $quiet = $this->removeFlag($argv, '--quiet');
        $color = !$this->removeFlag($argv, '--no-color') && $this->supportsColor();
        $name = array_shift($argv);

        if ($name === null || in_array($name, ['help', '--help', '-h'], true)) {
            if (!$quiet) {
                $this->printHelp();
            }
            return 0;
        }
        if (!isset($this->commands[$name])) {
            fwrite(STDERR, "Unknown command: {$name}\n\n");
            $this->printHelp();
            return 1;
        }
        if (in_array('--help', $argv, true) || in_array('-h', $argv, true)) {
            echo $this->commands[$name]->usage() . "\n";
            return 0;
        }

        try {
            return $this->commands[$name]->execute($argv, $quiet, $color);
        } catch (\Throwable $exception) {
            fwrite(STDERR, "PHPSEC: {$exception->getMessage()}\n");
            return 1;
        }
    }

    private function removeFlag(array &$arguments, string $flag): bool
    {
        $found = false;
        $arguments = array_values(array_filter($arguments, static function (string $argument) use ($flag, &$found): bool {
            if ($argument === $flag) {
                $found = true;
                return false;
            }
            return true;
        }));
        return $found;
    }

    private function supportsColor(): bool
    {
        return DIRECTORY_SEPARATOR !== '\\' || getenv('ANSICON') !== false || getenv('WT_SESSION') !== false;
    }

    private function printHelp(): void
    {
        echo "PHPSEC 2.0 — defensive PHP static analysis\n\nUsage: php phpsec.php <command> [options]\n\nCommands:\n";
        foreach ($this->commands as $command) {
            printf("  %-10s %s\n", $command->name(), $command->description());
        }
        echo "\nGlobal options: --quiet  --no-color  --help\n";
    }
}
