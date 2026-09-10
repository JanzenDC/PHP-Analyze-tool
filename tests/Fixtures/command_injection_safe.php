<?php
$host = escapeshellarg($_GET['host']);
system('ping ' . $host);
