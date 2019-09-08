CREATE TABLE IF NOT EXISTS `banned_players` (
  `id` int NOT NULL AUTO_INCREMENT,
  `player` varchar(32) DEFAULT NULL,
  `reason` varchar(191) DEFAULT NULL,
  `who_banned` varchar(64) DEFAULT NULL,
  `banned_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `banned_players_player_key` (`player`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS `ids` (
  `id` int NOT NULL AUTO_INCREMENT,
  `player` varchar(32) DEFAULT NULL,
  `ip` varchar(40) DEFAULT NULL,
  `ticket` varchar(64) DEFAULT NULL,
  `launcher_ver` varchar(32) DEFAULT NULL,
  `os` varchar(32) DEFAULT NULL,
  `os_arch` varchar(32) DEFAULT NULL,
  `os_version` varchar(64) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS `players` (
  `id` int NOT NULL AUTO_INCREMENT,
  `player` varchar(32) DEFAULT NULL,
  `skin` varchar(64) DEFAULT NULL,
  `skin_model` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL,
  `salt` varchar(64) DEFAULT NULL,
  `isMod` boolean DEFAULT FALSE,
  `isMojang` boolean DEFAULT FALSE,
  `cape` varchar(64) DEFAULT NULL,
  `clientToken` varchar(64) DEFAULT NULL,
  `accessToken` varchar(64) DEFAULT NULL,
  `serverId` varchar(64) DEFAULT NULL,
  `registered_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `players_player_key` (`player`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS `unbanned_players` (
  `id` int NOT NULL AUTO_INCREMENT,
  `player` varchar(32) DEFAULT NULL,
  `reason` varchar(191) DEFAULT NULL,
  `who_unbanned` varchar(64) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS `migration_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(64) NOT NULL,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `migration_history_title_key` (`title`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
