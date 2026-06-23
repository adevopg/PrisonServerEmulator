-- ============================================================================
--  03_login_states.sql  —  Columnas para la validación de login y estados
-- ============================================================================
--  Añade a 'accounts' lo necesario para:
--    - validar la contraseña (hash que envía el cliente)
--    - ban temporal (hasta una fecha)
--    - tiempo de juego / suscripción (caduca en una fecha)
--  Ejecutar después de 01_schema.sql:
--    mysql -u Inna -pLadyamy89 < sql/03_login_states.sql
-- ============================================================================
USE prison;

-- MySQL 8.0 no admite "ADD COLUMN IF NOT EXISTS", así que se añaden directamente.
-- (Si ya existen, MySQL dará un error que puedes ignorar.)
--
--  password_hash      : hash que envía el cliente (21 bytes -> 42 hex). Si está
--                       vacío/NULL el servidor deja pasar y REGISTRA el hash en
--                       el log para que lo copies aquí; al rellenarlo, se exige.
--  banned_until       : ban temporal; si está en el futuro, baneada hasta esa fecha.
--  subscription_until : tiempo de juego; si está en el pasado, "sin tiempo".
--                       NULL = ilimitado (cuentas gratuitas o sin caducidad).
ALTER TABLE accounts
  ADD COLUMN password_hash      VARCHAR(64) NULL AFTER password,
  ADD COLUMN banned_until       DATETIME    NULL AFTER banned,
  ADD COLUMN subscription_until DATETIME    NULL AFTER account_type;

-- Hash conocido de la cuenta de ejemplo 'innapmine' (contraseña Ladyamy89),
-- capturado del cliente real. Si tu cliente envía otro, cópialo del log del
-- servidor ("hash recibido=...") y actualízalo aquí.
UPDATE accounts
   SET password_hash = 'bed46e71a7d7697eb2ba4c71b3c3617dae823910d7'
 WHERE username = 'innapmine' AND (password_hash IS NULL OR password_hash = '');
