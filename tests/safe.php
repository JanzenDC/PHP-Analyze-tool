<?php
// Safe 1: prepared statement, no string built with user input
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Safe 2: input cast to int before use
$page = (int) $_GET['page'];
$sql = "SELECT * FROM posts LIMIT 10 OFFSET " . $page;
mysqli_query($conn, $sql);

// Safe 3: input escaped before use
$name = $_POST['name'];
$safeName = mysqli_real_escape_string($conn, $name);
$query = "SELECT * FROM accounts WHERE name = '" . $safeName . "'";
mysqli_query($conn, $query);
