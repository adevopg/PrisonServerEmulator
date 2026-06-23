-- ============================================================================
--  13_atributos_personaje.sql  —  Guardar los atributos repartidos del personaje
-- ============================================================================
--  Al crear un personaje, el cliente envía (en el mensaje 0x1394, offset 0x32)
--  los 6 atributos que el jugador repartió, como 6 words en este orden:
--     Fuerza, Destreza, Agilidad, Constitucion, Inteligencia, Carisma
--  Los guardamos en columnas propias para que queden en la BD y se puedan
--  mostrar en la lista de personajes (el cliente los lee en el slot +0x41..+0x4b).
--    mysql -u Inna -pLadyamy89 < sql/13_atributos_personaje.sql
-- ============================================================================
USE prison;

ALTER TABLE characters ADD COLUMN fuerza       SMALLINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN destreza     SMALLINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN agilidad     SMALLINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN constitucion SMALLINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN inteligencia SMALLINT UNSIGNED NOT NULL DEFAULT 0;
ALTER TABLE characters ADD COLUMN carisma      SMALLINT UNSIGNED NOT NULL DEFAULT 0;

-- Backfill: los personajes ya creados llevan los atributos dentro del blob
-- 'appearance' en el offset 0x32 (cada atributo es un word little-endian de 2 bytes).
--   byte = SUBSTRING(appearance, pos, 1) ; word = low + high*256   (pos en base 1)
UPDATE characters SET
  fuerza       = IFNULL(ASCII(SUBSTRING(appearance,0x33,1)),0) + IFNULL(ASCII(SUBSTRING(appearance,0x34,1)),0)*256,
  destreza     = IFNULL(ASCII(SUBSTRING(appearance,0x35,1)),0) + IFNULL(ASCII(SUBSTRING(appearance,0x36,1)),0)*256,
  agilidad     = IFNULL(ASCII(SUBSTRING(appearance,0x37,1)),0) + IFNULL(ASCII(SUBSTRING(appearance,0x38,1)),0)*256,
  constitucion = IFNULL(ASCII(SUBSTRING(appearance,0x39,1)),0) + IFNULL(ASCII(SUBSTRING(appearance,0x3A,1)),0)*256,
  inteligencia = IFNULL(ASCII(SUBSTRING(appearance,0x3B,1)),0) + IFNULL(ASCII(SUBSTRING(appearance,0x3C,1)),0)*256,
  carisma      = IFNULL(ASCII(SUBSTRING(appearance,0x3D,1)),0) + IFNULL(ASCII(SUBSTRING(appearance,0x3E,1)),0)*256
WHERE appearance IS NOT NULL AND LENGTH(appearance) >= 0x3E;
