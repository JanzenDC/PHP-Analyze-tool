<?php
declare(strict_types=1);

$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($connection, $sql);
