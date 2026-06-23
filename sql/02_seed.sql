USE prison;

-- Cuenta de juego: innapmine (GameMaster, gm_level 5).
-- password_hash = hash que envía el cliente para la contraseña Ladyamy89
-- (capturado del cliente real). Si tu cliente envía otro, cópialo del log
-- del servidor ("hash recibido=...") y actualízalo aquí.
INSERT INTO accounts (username, password_hash, gm_level)
VALUES ('innapmine', 'bed46e71a7d7697eb2ba4c71b3c3617dae823910d7', 5)
ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), gm_level=VALUES(gm_level);

-- Servidor de mundo local que aparece en la lista de prisiones.
INSERT INTO game_servers (name, online, population, sort_order)
VALUES ('La Prision - Local', 1, 0, 0)
ON DUPLICATE KEY UPDATE name=VALUES(name), online=VALUES(online);
