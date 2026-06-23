# PrisonServer — servidor emulador de "La Prisión" (Carcelclient.exe)

Servidor C++ desde cero para el MMO 3D español *La Prisión*, mediante ingeniería
inversa del cliente `Carcelclient.exe`. Login por **UDP 25666**, updates **UDP 25667**.
Base de datos **MySQL** (usuario `Inna` / `Ladyamy89`, BD `prison`). Cuenta de juego:
**`innapmine` / `Ladyamy89`**.

## Estado actual

| Componente | Estado |
|---|---|
| Transporte UDP-fiable "SNS" (handshake, cifrado XOR, ACK) | ✅ Funciona |
| Conexión del cliente real (innapmine) | ✅ Conecta y se mantiene estable |
| Envío fiable servidor→cliente | ✅ Funciona (el cliente lo confirma con ACK) |
| Autenticación contra MySQL | ✅ Busca la cuenta en `prison.accounts` |
| Listener de updates 25667 | ✅ Escucha (el cliente usa HTTP bajo demanda, no UDP, al arrancar) |
| Respuesta de login a nivel de aplicación → menú de servidores | ⏳ Pendiente (formato del mensaje "login OK" en ingeniería inversa) |
| Mundo de juego (movimiento, salas, combate…) | ⏳ Pendiente |

## Estructura del proyecto

El servidor está **modularizado**: cada archivo tiene una sola responsabilidad
y un encabezado que explica para qué sirve. La red usa **Boost.Asio** y se
compila con **CMake**.

```
CMakeLists.txt             Receta de compilación (Boost + MySQL)  ← sustituye a los .bat
build_cmake.bat            Atajo: prepara el compilador VS y llama a CMake

include/prison/            CABECERAS (.hpp) — qué ofrece cada módulo
  utilidades.hpp             Leer/escribir números en la red + clave de conexión
  registro.hpp               Mensajes/logs (consola + archivo)
  cifrado.hpp                Cifrado XOR del SNS + compresión zlib "stored"
  protocolo_sns.hpp          Constantes del protocolo SNS (offsets, flags, tipos)
  conexion.hpp               Estado de UN cliente (id, clave, fase, contadores)
  base_datos.hpp             Acceso a MySQL (cuentas y servidores)
  servidor_udp.hpp           Servidor UDP base con Boost.Asio (recibir/enviar)
  servidor_login.hpp         Servidor de LOGIN  (UDP 25666)
  servidor_mundo.hpp         Servidor de MUNDO  (UDP 25001)
  servidor_updates.hpp       Servidor de UPDATES(UDP 25667)

src/                       IMPLEMENTACIÓN (.cpp) — cómo lo hace cada módulo
  main.cpp                   Arranca los tres servidores (cada uno en su hilo)
  registro.cpp / cifrado.cpp / protocolo_sns.cpp / base_datos.cpp
  servidor_udp.cpp / servidor_login.cpp / servidor_mundo.cpp / servidor_updates.cpp
  diag_capture.cpp           Herramienta de captura (UDP+TCP, volcado hex)

sql/01_schema.sql          Esquema mínimo (solo accounts y game_servers, lo que usa el servidor)
sql/02_seed.sql            Cuenta innapmine (con hash) + servidor de juego local
sql/04_limpieza.sql        Quita de una BD vieja las columnas/tablas no usadas
analysis/*.py              Scripts de desensamblado (pefile + capstone)
legacy/                    El servidor antiguo (un solo archivo) como referencia
build/                     Carpeta de compilación (la genera CMake)
login_server.log           Registro del servidor
```

### ¿Qué hace cada cosa? (resumen rápido)

| Módulo            | Para qué sirve |
|-------------------|----------------|
| **utilidades**    | Convierte bytes ↔ números (la red usa little-endian). |
| **registro**      | Escribe logs con hora en consola y archivo. |
| **cifrado**       | Cifra/descifra los datos (XOR) y comprime listas (zlib). |
| **protocolo_sns** | Define la cabecera de 22 bytes y los nombres de cada campo. |
| **conexion**      | Guarda el estado de cada cliente conectado. |
| **base_datos**    | Único sitio que habla con MySQL (login, servidores). |
| **servidor_udp**  | Toda la RED (Boost.Asio): abrir socket, recibir y enviar. |
| **servidor_login**| Login, autenticación y selección de servidor (25666). |
| **servidor_mundo**| El juego: PONG y aparición del jugador (25001). |
| **servidor_updates** | Escucha actualizaciones y las registra (25667). |

## Cómo compilar (CMake)

1. MySQL en marcha (servicio `MySQL80`). Crear esquema/datos:
   ```
   mysql -u Inna -pLadyamy89 < sql/01_schema.sql
   mysql -u Inna -pLadyamy89 < sql/02_seed.sql
   ```
2. Compilar de cualquiera de estas dos formas:
   - **Fácil:** ejecutar `build_cmake.bat` (prepara Visual Studio y compila).
   - **Manual:** en una consola con el compilador de VS disponible:
     ```
     cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
     cmake --build build
     ```
   Dependencias (rutas por defecto, cambiables con `-DBOOST_ROOT=...` y
   `-DMYSQL_DIR=...`): Boost en `C:/local/boost_1_83_0`, MySQL en
   `C:/Program Files/MySQL/MySQL Server 8.0`.
3. Arrancar: `build\login_server.exe` (la `libmysql.dll` se copia sola al lado).
4. El cliente debe apuntar a 127.0.0.1: en
   `PrisonServer\LaPrision.ini` → `[LoginServer] IP=127.0.0.1 port=25666`,
   `[UpdatesServer] IP=127.0.0.1 port=25667`.
5. Ejecutar `Carcelclient.exe`. El servidor registra el handshake y los datos.

> **Nota:** si al arrancar ves «No se pudo atar al puerto 25666», es que ya
> hay otra instancia del servidor corriendo (ciérrala antes).

## Protocolo SNS (resumen de la ingeniería inversa)

Cabecera de 22 bytes (`0x16`):
```
[0x00] u32 connID_lo   (0xFFFFFFFF durante el handshake)
[0x04] u32 connID_hi   (= connID asignado en la fase de datos)
[0x08] u16 flags       (bit0=needs-ack, bit1=is-ack, bit2=has-data; <=7)
[0x0a] u8  window      (!= 0)
[0x0b] u8  ack         (< window)
[0x0c] u32 field_c     (id de mensaje; el ACK lo repite para emparejar)
[0x10] u32 timestamp
[0x14] u16 seq
[0x16] payload (cifrado XOR en la fase de datos; en claro en el handshake)
```
Handshake: cliente→SYN(tipo3, lleva el usuario) → servidor→SYN-ACK(tipo6, asigna
connID + material de clave) → cliente→ACK(tipo7) → establecido. Clave XOR `K`:
el servidor la codifica en `f1=((TS^K)&0x7e34fc22)^K` (off 0x10) y
`f2=((TS^K)&0x7e34fc22)^TS` (off 0x0c); el cliente recupera `K=((f1^f2)&M)^f1`.
Cifrado de datos: XOR encadenado, `out=K[(i>>2)&3]^in^i^prev`, semilla `0x3b`.

Detalle ampliado en la memoria del proyecto (`memory/prisonserver-emulator.md`).
