USE prison;

-- Cuenta de juego: innapmine (GameMaster, gm_level 5).
-- password_hash = hash que envía el cliente para la contraseña Ladyamy89
-- (capturado del cliente real). Si tu cliente envía otro, cópialo del log
-- del servidor ("hash recibido=...") y actualízalo aquí.
-- created_at en el pasado para que la cuenta de ejemplo esté activa al instante.
INSERT INTO accounts (username, password_hash, gm_level, created_at)
VALUES ('innapmine', 'bed46e71a7d7697eb2ba4c71b3c3617dae823910d7', 5, '2000-01-01 00:00:00')
ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), gm_level=VALUES(gm_level);

-- Prisiones que aparecen en la lista de selección (todo viene de MySQL).
-- (>= 2 para que el cliente NO auto-avance y se quede en la lista.)
INSERT INTO game_servers (id, name, name2, flag, extra, online, population, sort_order) VALUES
  (1, 'La Prision - Local', '', 2, 0, 1, 0, 0),
  (2, 'La Prision II',      '', 2, 0, 1, 0, 1)
ON DUPLICATE KEY UPDATE
  name=VALUES(name), name2=VALUES(name2), flag=VALUES(flag),
  extra=VALUES(extra), online=VALUES(online), sort_order=VALUES(sort_order);
