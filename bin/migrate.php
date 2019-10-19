#!/usr/bin/env php
<?php
define('BASEDIR', dirname(__FILE__, 2));
define('CONFIGDIR', BASEDIR . DIRECTORY_SEPARATOR . 'config');
define('SOURCEDIR', BASEDIR . DIRECTORY_SEPARATOR . 'src');

require_once SOURCEDIR . DIRECTORY_SEPARATOR . 'functions.php';

$conn = dbconn();

$migrations = [];
$migrations[] = [
    'title'    => 'added_skin_models_support',
    'function' => function (PDO $conn) {
        $conn->query('ALTER TABLE players ADD skin_model VARCHAR(64) DEFAULT NULL AFTER skin');
        $conn->query('ALTER TABLE players ADD cape VARCHAR(64) DEFAULT NULL AFTER isCapeOn');
        $conn->query('UPDATE players SET cape = player WHERE isCapeOn = TRUE');
        $conn->query('ALTER TABLE players DROP COLUMN isCapeOn');
    },
];

function migration_history_exist(PDO $conn): bool
{
    try {
        $result = $conn->query('SELECT TRUE FROM migration_history LIMIT 1');
    } catch (\PDOException $e) {
        return false;
    }
    return ($result !== false);
}

if (!migration_history_exist($conn)) {
    if ($conn->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql') {
        $autoIncrement = 'GENERATED BY DEFAULT AS IDENTITY';
        $timestampType = 'TIMESTAMP';
    } else {
        $autoIncrement = 'AUTO_INCREMENT';
        $timestampType = 'DATETIME';
    }
    $conn->query(sprintf(
        'CREATE TABLE migration_history ' .
        '(id INTEGER PRIMARY KEY %s, title VARCHAR(64) UNIQUE NOT NULL, timestamp %s DEFAULT CURRENT_TIMESTAMP)',
        $autoIncrement,
        $timestampType
    ));
}

$stmt = $conn->prepare('SELECT COUNT(*) FROM migration_history WHERE title = ?');
foreach ($migrations as $k => &$v) {
    $stmt->execute([$migrations[$k]['title']]);
    if ((int) $stmt->fetchColumn() == 0) {
        $migrations[$k]['function']($conn);
        $insert_stmt = $conn->prepare(
            'INSERT INTO migration_history (title) VALUES (?)'
        );
        $insert_stmt->execute([$migrations[$k]['title']]);
    }
}
