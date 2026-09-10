<?php
declare(strict_types=1);

$statement = $connection->prepare('SELECT * FROM users WHERE id = ?');
$statement->bind_param('i', $_GET['id']);
$statement->execute();
