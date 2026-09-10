<?php
$file = $_GET['file'];
readfile(__DIR__ . '/documents/' . $file);
