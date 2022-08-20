<?php

declare(strict_types=1);

define('TEST_ASSETS_DIR', __DIR__ . '/assets');
require_once dirname(__DIR__) . '/vendor/autoload.php';
// set default timezone
$tz = ini_get('date.timezone');
if ($tz === false || $tz === '') {
    ini_set('date.timezone', 'UTC');
}
