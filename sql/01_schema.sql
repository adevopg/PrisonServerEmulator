-- PrisonServer (La Prisión / Carcelclient) emulator schema
-- Connects with MySQL user: Inna / Ladyamy89
CREATE DATABASE IF NOT EXISTS prison
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_spanish_ci;

USE prison;

-- ---------------------------------------------------------------
-- Accounts (login)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(32)  NOT NULL,
  password      VARCHAR(64)  NOT NULL,          -- plaintext for now; capture decides hashing
  email         VARCHAR(128) NULL,
  gm_level      TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- 0 = free/normal, >0 = GameMaster
  account_type  TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- 0 free, 1 premium
  banned        TINYINT UNSIGNED NOT NULL DEFAULT 0,
  last_login    DATETIME NULL,
  last_ip       VARCHAR(45) NULL,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_username (username)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Characters
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS characters (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  account_id    INT UNSIGNED NOT NULL,
  slot          TINYINT UNSIGNED NOT NULL DEFAULT 0,
  nick          VARCHAR(32) NOT NULL,
  sex           TINYINT UNSIGNED NOT NULL DEFAULT 0,
  level         INT UNSIGNED NOT NULL DEFAULT 1,
  experience    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  money         BIGINT UNSIGNED NOT NULL DEFAULT 0,
  room          INT UNSIGNED NOT NULL DEFAULT 0,     -- map/room id
  pos_x         FLOAT NOT NULL DEFAULT 0,
  pos_y         FLOAT NOT NULL DEFAULT 0,
  pos_z         FLOAT NOT NULL DEFAULT 0,
  appearance    BLOB NULL,                            -- traje/aspect data, decided by capture
  deleted       TINYINT UNSIGNED NOT NULL DEFAULT 0,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_nick (nick),
  KEY idx_account (account_id),
  CONSTRAINT fk_char_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Game world servers shown in the server-selection list
-- (LOGINCMD_GETAVAILABLESERVERS)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS game_servers (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name          VARCHAR(64) NOT NULL,
  ip            VARCHAR(64) NOT NULL,
  port          INT UNSIGNED NOT NULL,
  online        TINYINT UNSIGNED NOT NULL DEFAULT 1,
  population     INT UNSIGNED NOT NULL DEFAULT 0,
  max_population INT UNSIGNED NOT NULL DEFAULT 200,
  sort_order    INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
) ENGINE=InnoDB;
