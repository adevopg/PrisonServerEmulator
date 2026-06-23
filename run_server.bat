@echo off
REM ============================================================================
REM  run_server.bat  —  Arranca el PrisonServer con la configuración que hace
REM                     funcionar el "JUGAR" (entrada al mundo / aparición).
REM ============================================================================
REM
REM  El comportamiento de entrada al juego se controla con VARIABLES DE ENTORNO
REM  (porque sigue en fase de ingeniería inversa). Sin ellas, al pulsar JUGAR
REM  el cliente entra al mundo pero el servidor no le envía la secuencia de
REM  aparición -> "no pasa nada" / pantalla negra.
REM
REM  Estas son las variables y para qué sirve cada una:
REM
REM    SPAWN=1      Activa la secuencia de APARICIÓN del jugador cuando el
REM                 cliente envía PASSDOOR (opcode 0x138e) en el mundo.
REM    ROOM=1       Envía la configuración de SALA/MAPA/OBJETOS antes de
REM                 aparecer (SERVERPARAMS, MAPINFO, OBJECTINFO, ROOMPARAMS).
REM    MAP=0xff     Selector de mapa = 0xff -> la puerta se trata como "start"
REM                 (punto de inicio); imprescindible para que aparezca.
REM    CLASSINFO=1  Envía la tabla de clases (evita un null-deref en el preview
REM                 de selección de prisión).
REM    MAPNAME=patio  Nombre del mapa donde aparece (puedes cambiarlo).
REM    PNAME=Innamine Nombre del jugador que aparece.
REM    PID=1          Id del jugador.
REM
REM  Para experimentar con otros valores, edítalos abajo.
REM ============================================================================

set SPAWN=1
set ROOM=1
set MAP=0xff
set CLASSINFO=1
set MAPNAME=patio
set PNAME=Innamine
set PID=1

REM (Opcionales — descomenta si los necesitas)
REM set RICH_LIST=1
REM set RECLUSOS=42
REM set PRISON_NAME=La Prision

echo ============================================================
echo  PrisonServer  ^|  SPAWN=%SPAWN% ROOM=%ROOM% MAP=%MAP% CLASSINFO=%CLASSINFO%
echo  Mapa=%MAPNAME%  Jugador=%PNAME% (id %PID%)
echo ============================================================
echo.

"%~dp0build\login_server.exe"
