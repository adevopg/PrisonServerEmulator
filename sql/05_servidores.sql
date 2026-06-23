-- ============================================================================
--  05_servidores.sql  —  Columnas nuevas de game_servers (lista de prisiones)
-- ============================================================================
--  Añade a una BD existente las columnas que el cliente espera por prisión
--  (SERVERADDED 0x13a9 / AVAILABLESERVERS 0x13ac) y siembra 2 prisiones.
--    mysql -u Inna -pLadyamy89 < sql/05_servidores.sql
--  (Si una columna ya existe, MySQL da un error que puedes ignorar.)
-- ============================================================================
USE prison;

ALTER TABLE game_servers
  ADD COLUMN name2 VARCHAR(64)     NOT NULL DEFAULT '' AFTER name,
  ADD COLUMN flag  TINYINT UNSIGNED NOT NULL DEFAULT 2 AFTER name2,
  ADD COLUMN extra INT UNSIGNED    NOT NULL DEFAULT 0  AFTER flag;

-- Prisiones de ejemplo (>= 2 para que la lista no auto-avance).
INSERT INTO game_servers (id, name, name2, flag, extra, online, population, sort_order) VALUES
  (1, 'La Prision - Local', '', 2, 0, 1, 0, 0),
  (2, 'La Prision II',      '', 2, 0, 1, 0, 1)
ON DUPLICATE KEY UPDATE
  name=VALUES(name), name2=VALUES(name2), flag=VALUES(flag),
  extra=VALUES(extra), online=VALUES(online), sort_order=VALUES(sort_order);
