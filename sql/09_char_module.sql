-- ============================================================================
--  09_char_module.sql  —  Cada personaje recuerda su módulo de celdas
-- ============================================================================
--  Además de la prisión (server_id), cada personaje pertenece a un MÓDULO de
--  celdas (1..modules de esa prisión). Se guarda al crearlo.
--    mysql -u Inna -pLadyamy89 < sql/09_char_module.sql
-- ============================================================================
USE prison;

ALTER TABLE characters
  ADD COLUMN module TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER server_id;
