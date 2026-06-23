@echo off
REM ============================================================
REM  build_cmake.bat  —  Configura y compila el PrisonServer
REM  con CMake usando el compilador de Visual Studio (Insiders).
REM ============================================================
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (echo [ERROR] vcvars no encontrado & exit /b 1)

cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (echo [ERROR] configuracion CMake fallo & exit /b 1)

cmake --build build
if errorlevel 1 (echo [ERROR] compilacion fallo & exit /b 1)

echo.
echo [OK] Compilado. Ejecutable en: build\login_server.exe
