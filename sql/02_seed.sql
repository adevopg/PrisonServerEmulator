USE prison;

-- Game account requested by the user: innapmine / Ladyamy89 (GameMaster)
INSERT INTO accounts (username, password, email, gm_level, account_type)
VALUES ('innapmine', 'Ladyamy89', 'adevopg@gmail.com', 5, 1)
ON DUPLICATE KEY UPDATE password=VALUES(password), gm_level=VALUES(gm_level), account_type=VALUES(account_type);

-- One game world server pointing at the local game server (added later).
INSERT INTO game_servers (name, ip, port, online, population, max_population, sort_order)
VALUES ('La Prision - Local', '127.0.0.1', 25668, 1, 0, 200, 0)
ON DUPLICATE KEY UPDATE ip=VALUES(ip), port=VALUES(port);
