-- ============================================================================
--  07_modules.sql  —  Separa "módulos de celdas" de "reclusos" en la prisión
-- ============================================================================
--  El cliente usa DOS valores independientes por prisión en AVAILABLESERVERS:
--    - nº de caracteres del texto      -> nº de MÓDULOS de celdas (1..N)
--    - suma del valor de los caracteres -> nº de RECLUSOS (población)
--  Antes ambos salían del mismo 'population' (por eso se compartían). Ahora:
--    modules    = nº de módulos de celdas (normalmente 4)
--    population = reclusos
--    mysql -u Inna -pLadyamy89 < sql/07_modules.sql
-- ============================================================================
USE prison;

ALTER TABLE game_servers
  ADD COLUMN modules TINYINT UNSIGNED NOT NULL DEFAULT 4 AFTER population;

-- Por defecto 4 módulos por prisión.
UPDATE game_servers SET modules = 4 WHERE modules = 0;
