@echo off
REM ============================================================================
REM  run_server.bat  —  Arranca el PrisonServer
REM ============================================================================
REM
REM  Toda la configuración está en  variables_entorno.bat  (edítalo ahí).
REM  Este script solo carga esas variables y lanza el ejecutable.
REM ============================================================================

REM Cargar TODAS las variables de entorno desde el archivo de configuración.
call "%~dp0variables_entorno.bat"

echo ============================================================
echo  PrisonServer  ^|  SPAWN=%SPAWN% ROOM=%ROOM% MAP=%MAP% CLASSINFO=%CLASSINFO%
echo  Mapa=%MAPNAME%  Jugador=%PNAME% (id %PID%)
echo ============================================================
echo.

"%~dp0build\login_server.exe"
