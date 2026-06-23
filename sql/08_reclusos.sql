-- ============================================================================
--  08_reclusos.sql  —  Reclusos dinámicos (= nº de personajes por prisión)
-- ============================================================================
--  Los "reclusos" ya NO son un valor fijo: se cuentan al vuelo como el número
--  de personajes creados en CADA prisión. Para eso:
--    - characters gana 'server_id' (la prisión a la que pertenece el personaje).
--    - game_servers pierde 'population' (ya no se usa).
--    mysql -u Inna -pLadyamy89 < sql/08_reclusos.sql
--  (Si una columna ya existe/no existe, MySQL da un error que puedes ignorar.)
-- ============================================================================
USE prison;

ALTER TABLE characters
  ADD COLUMN server_id INT UNSIGNED NOT NULL DEFAULT 1 AFTER account_id;

ALTER TABLE game_servers
  DROP COLUMN population;
