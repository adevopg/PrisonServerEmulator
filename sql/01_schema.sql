-- ============================================================================
--  01_schema.sql  —  Esquema MÍNIMO de PrisonServer (solo lo que usa el servidor)
-- ============================================================================
--  Se conecta con el usuario MySQL: Inna / Ladyamy89
--
--  El servidor SOLO lee estas dos tablas y estas columnas (nada más):
--    accounts     : id, username, password_hash, gm_level, banned,
--                   banned_until, subscription_until
--    game_servers : id, name, name2, flag, extra, population, online, sort_order
--  Cualquier columna/tabla extra se quitó por no usarse (ver 04_limpieza.sql).
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
  population  INT UNSIGNED NOT NULL DEFAULT 0,           -- "reclusos" mostrados
  sort_order  INT NOT NULL DEFAULT 0,                    -- orden en la lista
  PRIMARY KEY (id)
) ENGINE=InnoDB;
