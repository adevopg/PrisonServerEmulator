@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if not exist bin mkdir bin
set MYSQL=C:\Program Files\MySQL\MySQL Server 8.0
cl /nologo /EHsc /O2 /std:c++17 ^
   /I "%MYSQL%\include" ^
   src\sns_login_server.cpp ^
   /Fe:bin\login_server.exe /Fo:bin\ ^
   ws2_32.lib /link /LIBPATH:"%MYSQL%\lib"
REM copy libmysql.dll next to the exe for runtime
if not exist bin\libmysql.dll copy "%MYSQL%\lib\libmysql.dll" bin\ >nul
