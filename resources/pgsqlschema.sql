CREATE OR REPLACE FUNCTION updated_at_col_update() RETURNS TRIGGER AS $$
  BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
  END;
$$ LANGUAGE plpgsql;


CREATE TABLE IF NOT EXISTS "players" (
  "id" serial NOT NULL,
  "player" varchar(32) DEFAULT NULL UNIQUE,
  "skin" varchar(64) DEFAULT NULL,
  "skin_model" varchar(64) DEFAULT NULL,
  "password" varchar(64) DEFAULT NULL,
  "salt" varchar(64) DEFAULT NULL,
  "isMod" boolean DEFAULT FALSE,
  "isMojang" boolean DEFAULT FALSE,
  "cape" varchar(64) DEFAULT NULL,
  "clientToken" varchar(64) DEFAULT NULL UNIQUE,
  "accessToken" varchar(64) DEFAULT NULL UNIQUE,
  "serverId" varchar(64) DEFAULT NULL,
  "registered_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id")
);

DROP TRIGGER IF EXISTS "update_updated_at" ON "players";
CREATE TRIGGER "update_updated_at" BEFORE UPDATE ON "players"
FOR EACH ROW EXECUTE PROCEDURE updated_at_col_update();


CREATE TABLE IF NOT EXISTS "ids" (
  "id" serial NOT NULL,
  "player" varchar(32) DEFAULT NULL,
  "ip" varchar(40) DEFAULT NULL,
  "uuid" varchar(64) DEFAULT NULL,
  "ticket" varchar(64) DEFAULT NULL,
  "launcher_ver" varchar(32) DEFAULT NULL,
  "os" varchar(32) DEFAULT NULL,
  "os_arch" varchar(32) DEFAULT NULL,
  "os_version" varchar(64) DEFAULT NULL,
  "created_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id"),
  CONSTRAINT "ids_player_fkey"
    FOREIGN KEY ("player") REFERENCES "players" ("player")
    ON DELETE RESTRICT
    ON UPDATE RESTRICT
);


CREATE TABLE IF NOT EXISTS "banned_players" (
  "id" serial NOT NULL,
  "player" varchar(32) DEFAULT NULL UNIQUE,
  "reason" varchar(191) DEFAULT NULL,
  "who_banned" varchar(64) DEFAULT NULL,
  "banned_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id"),
  CONSTRAINT "banned_players_player_fkey"
    FOREIGN KEY ("player") REFERENCES "players" ("player")
    ON DELETE CASCADE
    ON UPDATE RESTRICT
);


CREATE TABLE IF NOT EXISTS "unbanned_players" (
  "id" serial NOT NULL,
  "player" varchar(32) DEFAULT NULL UNIQUE,
  "reason" varchar(191) DEFAULT NULL,
  "who_unbanned" varchar(64) DEFAULT NULL,
  "created_at" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id"),
  CONSTRAINT "unbanned_players_player_fkey"
    FOREIGN KEY ("player") REFERENCES "players" ("player")
    ON DELETE CASCADE
    ON UPDATE RESTRICT
);


CREATE TABLE IF NOT EXISTS "migration_history" (
  "id" serial NOT NULL,
  "title" varchar(64) NOT NULL UNIQUE,
  "timestamp" timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id")
);
