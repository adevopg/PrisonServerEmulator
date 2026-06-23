@echo off
REM Build the diagnostic capture tool with MSVC
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist bin mkdir bin
cl /nologo /EHsc /O2 /std:c++17 src\diag_capture.cpp /Fe:bin\diag_capture.exe /Fo:bin\ ws2_32.lib
