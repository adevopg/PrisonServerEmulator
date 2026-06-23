-- ============================================================================
--  01_schema.sql  —  Esquema MÍNIMO de PrisonServer (solo lo que usa el servidor)
-- ============================================================================
--  Se conecta con el usuario MySQL: Inna / Ladyamy89
--
--  Tablas que usa el servidor:
--    accounts     : id, username, password_hash, gm_level, banned,
--                   banned_until, subscription_until
--    game_servers : id, name, name2, flag, extra, population, online, sort_order
--    characters   : personajes creados (ver más abajo)
-- ============================================================================
CREATE DATABASE IF NOT EXISTS prison
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_spanish_ci;

USE prison;

-- ---------------------------------------------------------------
--  Cuentas (login + validación de estado)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
  id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username           VARCHAR(32)  NOT NULL,                 -- nombre de usuario (llega en el SYN)
  password_hash      VARCHAR(64)  NULL,                     -- hash que envía el cliente (hex); vacío = no validar
  gm_level           TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- 0 = jugador, >0 = GameMaster
  banned             TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- 1 = baneada permanentemente
  banned_until       DATETIME NULL,                         -- ban temporal: baneada hasta esta fecha
  subscription_until DATETIME NULL,                         -- tiempo de juego: NULL = ilimitado
  PRIMARY KEY (id),
  UNIQUE KEY uq_username (username)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
--  Prisiones / servidores de mundo (lista de selección del cliente)
--  Las columnas son las que el cliente lee en SERVERADDED (0x13a9) y
--  AVAILABLESERVERS (0x13ac).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS game_servers (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name        VARCHAR(64) NOT NULL,                      -- nombre mostrado de la prisión
  name2       VARCHAR(64) NOT NULL DEFAULT '',           -- segundo texto (se muestra "name name2")
  flag        TINYINT UNSIGNED NOT NULL DEFAULT 2,       -- byte que el cliente guarda en el nodo
  extra       INT UNSIGNED NOT NULL DEFAULT 0,           -- dword extra que guarda el cliente
  online      TINYINT UNSIGNED NOT NULL DEFAULT 1,       -- 1 = aparece en la lista
  modules     TINYINT UNSIGNED NOT NULL DEFAULT 4,       -- nº de módulos de celdas (= nº de caracteres)
  sort_order  INT NOT NULL DEFAULT 0,                    -- orden en la lista
  PRIMARY KEY (id)
  -- Los "reclusos" NO se guardan aquí: se cuentan al vuelo (personajes por prisión).
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
--  Personajes (se guardan al crearlos). Detalle en 06_characters.sql.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS characters (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  account_id  INT UNSIGNED NOT NULL,                  -- cuenta dueña (accounts.id)
  server_id   INT UNSIGNED NOT NULL DEFAULT 1,        -- prisión a la que pertenece (game_servers.id)
  module      TINYINT UNSIGNED NOT NULL DEFAULT 1,    -- módulo de celdas (1..modules de la prisión)
  slot        TINYINT UNSIGNED NOT NULL DEFAULT 0,    -- ranura (0..n) dentro de la cuenta
  nick        VARCHAR(32)  NOT NULL,                  -- nombre del personaje
  sex         TINYINT UNSIGNED NOT NULL DEFAULT 0,    -- sexo / género
  class       TINYINT UNSIGNED NOT NULL DEFAULT 0,    -- clase (índice)
  level       INT UNSIGNED NOT NULL DEFAULT 1,        -- nivel
  experience  BIGINT UNSIGNED NOT NULL DEFAULT 0,     -- experiencia
  money       BIGINT UNSIGNED NOT NULL DEFAULT 0,     -- dinero
  room        INT UNSIGNED NOT NULL DEFAULT 0,        -- sala/mapa actual
  pos_x       FLOAT NOT NULL DEFAULT 0,
  pos_y       FLOAT NOT NULL DEFAULT 0,
  pos_z       FLOAT NOT NULL DEFAULT 0,
  appearance  VARBINARY(1024) NULL,                   -- bloque crudo de aspecto/atributos
  deleted     TINYINT UNSIGNED NOT NULL DEFAULT 0,    -- 1 = borrado
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_nick (nick),
  KEY idx_account (account_id)
) ENGINE=InnoDB;
