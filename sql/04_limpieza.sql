-- ============================================================================
--  04_limpieza.sql  —  Quita de una BD existente todo lo que el servidor NO usa
-- ============================================================================
--  Ejecutar UNA vez sobre una base de datos creada con el esquema antiguo:
--    mysql -u Inna -pLadyamy89 < sql/04_limpieza.sql
--
--  Deja accounts y game_servers solo con las columnas que el servidor lee.
--  (Si una columna/tabla ya no existe, MySQL da un error que puedes ignorar.)
-- ============================================================================
USE prison;

-- Tabla que el servidor nunca consulta.
DROP TABLE IF EXISTS characters;

-- Columnas de 'accounts' que el servidor no usa.
ALTER TABLE accounts
  DROP COLUMN password,
  DROP COLUMN email,
  DROP COLUMN account_type,
  DROP COLUMN last_login,
  DROP COLUMN last_ip,
  DROP COLUMN created_at;

-- Columnas de 'game_servers' que el servidor no usa.
ALTER TABLE game_servers
  DROP COLUMN ip,
  DROP COLUMN port,
  DROP COLUMN max_population;
