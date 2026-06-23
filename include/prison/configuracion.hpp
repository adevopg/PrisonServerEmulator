// ============================================================================
//  configuracion.hpp  —  TODAS las variables de entorno en un solo sitio
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  Antes el código llamaba a getenv("SPAWN"), getenv("ROOM")... repartidos por
//  todos lados (difícil de ver qué se configura y fácil de escribir mal el
//  nombre). Ahora TODO se lee UNA sola vez, aquí, y el resto del servidor usa
//  campos con nombre claro:
//
//        antes:   if (getenv("SPAWN")) ...
//        ahora:   if (cfg().spawn) ...
//
//        antes:   getenv("PNAME") ? getenv("PNAME") : "Innamine"
//        ahora:   cfg().nombreJugador
//
//  Cada campo ya trae su valor por defecto aplicado. Las variables se definen
//  al arrancar (ver variables_entorno.bat).
// ============================================================================
#pragma once

#include <cstdint>
#include <string>

namespace prison {

struct Configuracion {
    // ---- GRUPO 1: entrada al juego (interruptores SÍ/NO) ----
    bool spawn      = false;  // SPAWN     : activa la aparición del jugador
    bool room       = false;  // ROOM      : envía config de sala/mapa/objetos
    bool classInfo  = false;  // CLASSINFO : envía la tabla de clases
    bool enterGame  = false;  // ENTER_GAME: responde al auto-select 0x139f

    // ---- GRUPO 2: datos del jugador y de la sala ----
    std::string nombreJugador = "Innamine"; // PNAME
    uint32_t    idJugador     = 1;          // PID
    std::string nombreMapa    = "patio";    // MAPNAME
    uint32_t    plantilla     = 1;          // TMPL
    uint32_t    idSala        = 1;          // RID
    int         mapa          = 0xfa;       // MAP (selector de mapa)

    // ---- GRUPO 3: lista de prisiones (lista "rica") ----
    bool        listaRica     = false;        // RICH_LIST
    std::string nombrePrision = "La Prision"; // PRISON_NAME
    uint32_t    reclusos      = 42;           // RECLUSOS

    // ---- GRUPO 4: avanzado / depuración ----
    int  tamPosicion   = 0x220; // POS_SZ : bytes del bloque de posición (opcode 2)
    int  tamDatosJug   = 0x220; // PD_SZ  : bytes del bloque del jugador (opcode 3)

    bool tieneStartFieldc = false; // START_FIELDC definida?
    int  startFieldc      = 0;     // START_FIELDC: id de mensaje inicial

    // Barrido de opcodes de diagnóstico en el mundo (solo si spawn = false).
    int  barridoDesde = 0x1388; // SWEEP_LO
    int  barridoHasta = 0x1480; // SWEEP_HI
    int  barridoMs    = 250;    // SWEEP_MS
};

// Devuelve la configuración (se lee de las variables de entorno la 1ª vez que
// se llama, y queda cacheada para el resto de la ejecución).
const Configuracion& cfg();

} // namespace prison
