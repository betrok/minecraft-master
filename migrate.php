<?php
require 'config.php';
require 'functions.php';

$db = newdb();

$migrations = [];
$migrations[] = [
	"title" => "added_skin_models_support",
	"function" => 
	function(){
		global $db;
		$db->query("ALTER TABLE players ADD skin_model VARCHAR(64) DEFAULT NULL AFTER skin");
		$db->query("ALTER TABLE players ADD cape VARCHAR(64) DEFAULT NULL AFTER isCapeOn");
		$db->query("UPDATE players SET cape = player WHERE isCapeOn = 1");
		$db->query("ALTER TABLE players DROP COLUMN isCapeOn");
	}
];

function migrationHistoryExist($db) {
	$result = $db->query("show tables");
	while ($row = $result->fetch_array()) {
		if ($row[0] == "migration_history"){
			return true;
		}
	}
	return false;
}

if (!migrationHistoryExist($db)) {
	$db->query("CREATE TABLE migration_history(id INTEGER PRIMARY KEY AUTO_INCREMENT, title VARCHAR(64) UNIQUE NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
}
$sql = $db->prepare("SELECT title FROM migration_history WHERE title=?");
for ($i = 0, $count = count($migrations); $i < $count; ++$i){
	$sql->bind_param('s', $migrations[$i]["title"]);
	$sql->execute();
	$sql->bind_result($title);
	$sql->store_result();
	if ($sql->num_rows == 0){
		$migrations[$i]["function"]();
		$insertsql = $db->prepare("INSERT INTO migration_history(title) VALUES(?)");
		$insertsql->bind_param("s", $migrations[$i]['title']);
		$insertsql->execute();
		$insertsql->close();
	}
	$sql->free_result();
}

?>