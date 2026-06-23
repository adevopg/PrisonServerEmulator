-- ============================================================================
--  06_characters.sql  —  Tabla de personajes (se guardan al crearlos)
-- ============================================================================
--  Guarda los personajes que crea el jugador. Las columnas con nombre son los
--  datos típicos de un personaje; "appearance" guarda el bloque crudo de
--  aspecto/atributos que envía el cliente al crear (hasta mapear cada campo a
--  su propia columna con la captura del paquete 0x1394).
--    mysql -u Inna -pLadyamy89 < sql/06_characters.sql
-- ============================================================================
USE prison;

CREATE TABLE IF NOT EXISTS characters (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  account_id  INT UNSIGNED NOT NULL,                  -- cuenta dueña (accounts.id)
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
  appearance  VARBINARY(1024) NULL,                   -- bloque crudo de aspecto/atributos (del cliente)
  deleted     TINYINT UNSIGNED NOT NULL DEFAULT 0,    -- 1 = borrado (no se muestra)
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_nick (nick),
  KEY idx_account (account_id)
) ENGINE=InnoDB;
