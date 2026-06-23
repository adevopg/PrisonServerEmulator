-- ============================================================================
--  10_account_activacion.sql  —  Activación diferida de cuentas nuevas
-- ============================================================================
--  Una cuenta nueva NO se reconoce hasta pasados 5 minutos desde que aparece en
--  la base de datos (created_at). Antes de eso, el login se rechaza con "DATOS
--  INCORRECTOS" (el cliente ya dice "si acaba de crear la cuenta, espere unos
--  minutos").
--    mysql -u Inna -pLadyamy89 < sql/10_account_activacion.sql
-- ============================================================================
USE prison;

ALTER TABLE accounts
  ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Las cuentas que YA existían se consideran activas (fecha en el pasado).
UPDATE accounts SET created_at = '2000-01-01 00:00:00';
