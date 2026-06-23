@echo off
REM ============================================================================
REM  variables_entorno.bat  —  TODAS las variables de configuración del servidor
REM ============================================================================
REM
REM  Este es el ÚNICO archivo que necesitas editar para configurar el servidor.
REM  Cada variable controla una parte del comportamiento. Lo llama run_server.bat
REM  justo antes de arrancar el ejecutable.
REM
REM  CÓMO ACTIVAR / DESACTIVAR una opción de tipo SÍ/NO:
REM     set SPAWN=1      -> ACTIVADA (cualquier valor vale, el código solo mira
REM                         si existe la variable)
REM     set SPAWN=       -> DESACTIVADA (vacía = como si no existiera)
REM
REM  Después de editar, guarda y arranca con run_server.bat.
REM ============================================================================


REM ============================================================================
REM  GRUPO 0 — LOGIN Y CUENTAS
REM ============================================================================

REM  MANTENIMIENTO: si está activa, el servidor rechaza a todos los jugadores
REM                 (los GameMaster SÍ pueden entrar). Mensaje "en mantenimiento".
set MANTENIMIENTO=

REM  EXIGIR_PASSWORD: si una cuenta NO tiene 'password_hash' guardado en la base
REM                   de datos, normalmente se deja pasar (y se registra el hash
REM                   en el log para que lo copies). Si activas esto, esas cuentas
REM                   se RECHAZAN hasta que guardes su hash.
set EXIGIR_PASSWORD=


REM ============================================================================
REM  GRUPO 1 — ENTRADA AL JUEGO (lo que hace funcionar el botón JUGAR)
REM ============================================================================

REM  SPAWN: activa la secuencia de APARICIÓN del jugador en el mundo cuando el
REM         cliente cruza la puerta (PASSDOOR 0x138e). Sin esto, al pulsar JUGAR
REM         entras al mundo pero no aparece nada (pantalla negra).
set SPAWN=1

REM  ROOM: antes de aparecer, envía la configuración de SALA/MAPA/OBJETOS
REM        (SERVERPARAMS, MAPINFO, OBJECTINFO, ROOMPARAMS). Necesario para SPAWN.
set ROOM=1

REM  MAP: selector de mapa. 0xff -> la puerta se trata como "start" (punto de
REM       inicio). Es el valor que hace aparecer al jugador en el patio.
set MAP=0xff

REM  CLASSINFO: envía la tabla de clases (evita un cuelgue en el preview de la
REM             pantalla de selección de prisión).
set CLASSINFO=1

REM  ENTER_GAME: (avanzado) responde también al auto-select 0x139f con permiso
REM              de entrada. Normalmente DESACTIVADO: el botón JUGAR (0x13f1) ya
REM              funciona sin esto. Actívalo solo para experimentar.
set ENTER_GAME=


REM ============================================================================
REM  GRUPO 2 — DATOS DEL JUGADOR Y DE LA SALA
REM ============================================================================

REM  PNAME: nombre del jugador que aparece en el mundo.
set PNAME=Innamine

REM  PID: id numérico del jugador.
set PID=1

REM  MAPNAME: nombre del mapa donde aparece (ej: patio, comedor, biblioteca...).
set MAPNAME=patio

REM  TMPL: id de la plantilla de sala (debe coincidir entre MAPINFO y ROOMPARAMS).
set TMPL=1

REM  RID: id de la sala (RoomID).
set RID=1


REM ============================================================================
REM  GRUPO 3 — LISTA DE SERVIDORES / PRISIONES (pantalla de selección)
REM ============================================================================

REM  RICH_LIST: envía la lista "rica" de prisiones (nombre + reclusos + archivo
REM             .skf, comprimida). Normalmente DESACTIVADO; la lista normal sale
REM             de la base de datos (game_servers).
set RICH_LIST=

REM  PRISON_NAME: nombre de la prisión en la lista rica (solo si RICH_LIST activo).
set PRISON_NAME=La Prision

REM  RECLUSOS: número de "reclusos" mostrado en la lista rica (solo con RICH_LIST).
set RECLUSOS=42


REM ============================================================================
REM  GRUPO 4 — AVANZADO / DEPURACIÓN (normalmente no hace falta tocar)
REM ============================================================================

REM  POS_SZ: tamaño (bytes) del bloque de posición al CREAR jugador (opcode 2).
set POS_SZ=

REM  PD_SZ: tamaño (bytes) del bloque de datos del jugador al ENTRAR (opcode 3).
set PD_SZ=

REM  START_FIELDC: valor inicial del id de mensaje saliente (campo_c). Para
REM                pruebas de continuidad de la conexión fiable.
set START_FIELDC=

REM  SWEEP_LO / SWEEP_HI / SWEEP_MS: "barrido" de opcodes de diagnóstico en el
REM     mundo (envía opcodes del LO al HI, esperando MS milisegundos entre cada
REM     uno) para descubrir cuáles reconoce el cliente. Solo se usa si SPAWN está
REM     DESACTIVADO. Déjalas vacías para no barrer.
set SWEEP_LO=
set SWEEP_HI=
set SWEEP_MS=
