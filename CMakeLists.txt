# ============================================================================
#  CMakeLists.txt  —  Cómo compilar el PrisonServer
# ============================================================================
#
#  ¿QUÉ ES CMAKE?
#  CMake genera los archivos de compilación (proyecto de Visual Studio, etc.)
#  a partir de esta receta. Sustituye a los antiguos build_login.bat.
#
#  CÓMO COMPILAR (desde la carpeta del proyecto, en una consola):
#
#      cmake -S . -B build
#      cmake --build build --config Release
#
#  El ejecutable queda en:  build/Release/login_server.exe
#
#  DEPENDENCIAS (rutas por defecto; cámbialas con -D si tienes otras):
#      - Boost   (BOOST_ROOT)  -> C:/local/boost_1_83_0   (Boost.Asio = la red)
#      - MySQL   (MYSQL_DIR)   -> C:/Program Files/MySQL/MySQL Server 8.0
# ============================================================================
cmake_minimum_required(VERSION 3.16)

project(PrisonServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
#  Rutas a las dependencias (se pueden cambiar al invocar cmake con -D...)
# ---------------------------------------------------------------------------
if(NOT DEFINED BOOST_ROOT)
    set(BOOST_ROOT "C:/local/boost_1_83_0" CACHE PATH "Carpeta raíz de Boost")
endif()

set(MYSQL_DIR "C:/Program Files/MySQL/MySQL Server 8.0" CACHE PATH "Carpeta de MySQL Server")

# ---------------------------------------------------------------------------
#  Buscar Boost (solo necesitamos las cabeceras: Boost.Asio es header-only)
# ---------------------------------------------------------------------------
find_package(Boost 1.70 REQUIRED)

# ---------------------------------------------------------------------------
#  Buscar MySQL (cabeceras + librería de importación libmysql.lib)
# ---------------------------------------------------------------------------
find_path(MYSQL_INCLUDE_DIR
    NAMES mysql.h
    PATHS "${MYSQL_DIR}/include"
    REQUIRED)

find_library(MYSQL_LIBRARY
    NAMES libmysql mysqlclient
    PATHS "${MYSQL_DIR}/lib"
    REQUIRED)

# ---------------------------------------------------------------------------
#  Servidor principal (login + mundo + updates)
# ---------------------------------------------------------------------------
add_executable(login_server
    src/main.cpp
    src/registro.cpp
    src/cifrado.cpp
    src/protocolo_sns.cpp
    src/configuracion.cpp
    src/base_datos.cpp
    src/servidor_udp.cpp
    src/servidor_login.cpp
    src/servidor_mundo.cpp
    src/servidor_updates.cpp
)

target_include_directories(login_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIRS}
    ${MYSQL_INCLUDE_DIR}
)

target_link_libraries(login_server PRIVATE
    ${MYSQL_LIBRARY}
    ws2_32       # Winsock (lo necesita Boost.Asio por debajo)
    mswsock
)

# En Windows hay que decir qué versión mínima de la API usamos (para Boost.Asio).
if(WIN32)
    target_compile_definitions(login_server PRIVATE
        _WIN32_WINNT=0x0601        # Windows 7 o superior
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS    # permite getenv/strcpy sin avisos
    )
endif()

# Copiar libmysql.dll junto al .exe para que pueda ejecutarse.
add_custom_command(TARGET login_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MYSQL_DIR}/lib/libmysql.dll"
            "$<TARGET_FILE_DIR:login_server>"
    COMMENT "Copiando libmysql.dll junto al ejecutable")

# ---------------------------------------------------------------------------
#  Herramienta de captura/diagnóstico (opcional)
# ---------------------------------------------------------------------------
add_executable(diag_capture src/diag_capture.cpp)
target_link_libraries(diag_capture PRIVATE ws2_32)
if(WIN32)
    target_compile_definitions(diag_capture PRIVATE
        _WIN32_WINNT=0x0601 _CRT_SECURE_NO_WARNINGS)
endif()
