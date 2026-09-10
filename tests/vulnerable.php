<?php
// Case 1: classic concatenation SQLi
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $sql);

// Case 2: string interpolation SQLi
$name = $_POST['name'];
$query = "SELECT * FROM accounts WHERE name = '$name'";
mysqli_query($conn, $query);

// Case 3: tainted value passed straight into PDO ->query()
$search = $_REQUEST['q'];
$stmt = $pdo->query("SELECT * FROM products WHERE title LIKE '%$search%'");
