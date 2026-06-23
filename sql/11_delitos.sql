-- ============================================================================
--  11_delitos.sql  —  Delitos (clases) y sus habilidades, EDITABLES en MySQL
-- ============================================================================
--  El servidor construye el mensaje CLASSINFO (la pantalla de creación de
--  personaje) a partir de estas tablas. Formato decodificado del cliente:
--    cabecera [N0 delitos][N1 atributos][N2 habilidades]
--    -> N1 nombres de atributo, N2 nombres de habilidad
--    -> por cada delito: nombre_fem, nombre_masc, "", 20 bytes,
--       N1 x (a0,a1)  [atributos]   y   N2 x (h0,h1,h2,h3)  [habilidades]
--  Los valores a0/a1 y h0..h3 son los bytes que envía el servidor oficial.
--  No los conocemos exactos, así que se guardan CRUDOS aquí y los puedes ajustar
--  hasta que coincidan con el oficial (cada fila = un delito x una habilidad).
--    mysql -u Inna -pLadyamy89 < sql/11_delitos.sql
-- ============================================================================
USE prison;

-- ---- Delitos (clases). id = índice de clase (char +0x40). ----
CREATE TABLE IF NOT EXISTS delitos (
  id         INT UNSIGNED NOT NULL,            -- índice de clase (0..N)
  nombre_m   VARCHAR(32) NOT NULL,             -- nombre masculino
  nombre_f   VARCHAR(32) NOT NULL,             -- nombre femenino
  sort_order INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
) ENGINE=InnoDB;

-- ---- Atributos (Fuerza, Destreza, ...). N1 = nº de filas. ----
CREATE TABLE IF NOT EXISTS atributos (
  id         INT UNSIGNED NOT NULL,
  nombre     VARCHAR(32) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
) ENGINE=InnoDB;

-- ---- Habilidades (Armas a distancia, Sigilo, ...). N2 = nº de filas. ----
CREATE TABLE IF NOT EXISTS habilidades (
  id         INT UNSIGNED NOT NULL,
  nombre     VARCHAR(48) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id)
) ENGINE=InnoDB;

-- ---- Valores de atributo por delito (2 bytes: a0, a1). ----
CREATE TABLE IF NOT EXISTS delito_atributo (
  delito_id   INT UNSIGNED NOT NULL,
  atributo_id INT UNSIGNED NOT NULL,
  a0          TINYINT UNSIGNED NOT NULL DEFAULT 10,   -- valor base del atributo
  a1          TINYINT UNSIGNED NOT NULL DEFAULT 0,    -- 1 = atributo principal (parpadea)
  PRIMARY KEY (delito_id, atributo_id)
) ENGINE=InnoDB;

-- ---- Habilidades por delito (datos del MANUAL). ----
--  Solo hay fila si el delito TIENE esa habilidad (si no, no aparece).
--    maximo  = "Puntos Máximos" del manual (el cliente lo muestra x1.5)
--    inicial = puntos al nivel 1 (1 normal, 0 si requiere entrenar a cierto nivel)
--    nivel   = nivel requerido para entrenarla (0 = disponible desde el nivel 1)
--  (La lista COMPLETA por delito se rellena en 12_habilidades.sql.)
CREATE TABLE IF NOT EXISTS delito_habilidad (
  delito_id    INT UNSIGNED NOT NULL,
  habilidad_id INT UNSIGNED NOT NULL,
  maximo       TINYINT UNSIGNED NOT NULL DEFAULT 100,
  inicial      TINYINT UNSIGNED NOT NULL DEFAULT 1,
  nivel        TINYINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (delito_id, habilidad_id)
) ENGINE=InnoDB;

-- ============================================================================
--  SEED: los 12 delitos, 6 atributos y una lista base de habilidades.
-- ============================================================================
INSERT INTO delitos (id, nombre_m, nombre_f, sort_order) VALUES
  (0,'Mercenario','Mercenaria',0),
  (1,'Asesino en serie','Asesina en serie',1),
  (2,'Asesino a sueldo','Asesina a sueldo',2),
  (3,'Hacker','Hacker',3),
  (4,'Politico corrupto','Politica corrupta',4),
  (5,'Timador','Timadora',5),
  (6,'Ladron','Ladrona',6),
  (7,'Narcotraficante','Narcotraficante',7),
  (8,'Atracador','Atracadora',8),
  (9,'Mafioso','Mafiosa',9),
  (10,'Canibal','Canibal',10),
  (11,'Pandillero','Pandillera',11)
ON DUPLICATE KEY UPDATE nombre_m=VALUES(nombre_m), nombre_f=VALUES(nombre_f);

INSERT INTO atributos (id, nombre, sort_order) VALUES
  (0,'Fuerza',0),(1,'Destreza',1),(2,'Agilidad',2),
  (3,'Constitucion',3),(4,'Inteligencia',4),(5,'Carisma',5)
ON DUPLICATE KEY UPDATE nombre=VALUES(nombre);

-- Lista base de habilidades (las 4 de combate las tienen todos + algunas comunes).
-- Puedes añadir más filas y asociarlas a cada delito en delito_habilidad.
INSERT INTO habilidades (id, nombre, sort_order) VALUES
  (0,'Armas a distancia',0),(1,'Armas blancas',1),(2,'Armas contundentes',2),
  (3,'Artes marciales',3),(4,'Esquivar',4),(5,'Aturdir',5),(6,'Sigilo',6),
  (7,'Robar',7),(8,'Forzar cerraduras',8),(9,'Primeros auxilios',9),
  (10,'Costura',10),(11,'Quimica',11),(12,'Cocina',12),(13,'Mecanica',13),
  (14,'Joyeria',14),(15,'Tolerancia quimica',15)
ON DUPLICATE KEY UPDATE nombre=VALUES(nombre);

-- Atributos por delito: baseline (todos los delitos x todos los atributos).
INSERT IGNORE INTO delito_atributo (delito_id, atributo_id, a0, a1)
  SELECT d.id, a.id, 10, 0 FROM delitos d CROSS JOIN atributos a;

-- Habilidades por delito: baseline con las 4 de combate para TODOS (para que
-- la lista aparezca). La lista COMPLETA y real se rellena en 12_habilidades.sql.
INSERT IGNORE INTO delito_habilidad (delito_id, habilidad_id, maximo, inicial, nivel)
  SELECT d.id, h.id, 150, 1, 0 FROM delitos d CROSS JOIN habilidades h WHERE h.id <= 3;
