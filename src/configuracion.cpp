// ============================================================================
//  configuracion.cpp  —  Lee TODAS las variables de entorno (ver .hpp)
// ============================================================================
#include "prison/configuracion.hpp"

#include <cstdlib>
#include <cstring>

namespace prison {

// --- Pequeños ayudantes para leer una variable de entorno con valor por defecto ---

// ¿Está definida (existe) la variable? (interruptores SÍ/NO)
static bool definida(const char* nombre) {
    return getenv(nombre) != nullptr;
}

// Texto; si no está definida, devuelve "porDefecto".
static std::string texto(const char* nombre, const char* porDefecto) {
    const char* v = getenv(nombre);
    return v ? std::string(v) : std::string(porDefecto);
}

// Entero (acepta hexadecimal "0x.." gracias a la base 0); si no, "porDefecto".
static long entero(const char* nombre, long porDefecto) {
    const char* v = getenv(nombre);
    return v ? strtol(v, nullptr, 0) : porDefecto;
}

// Lee toda la configuración desde las variables de entorno.
static Configuracion cargar() {
    Configuracion c;

    // Grupo 0: login y cuentas.
    c.mantenimiento    = definida("MANTENIMIENTO");
    c.exigirContrasena = definida("EXIGIR_PASSWORD");

    // Grupo 1: interruptores de entrada al juego.
    c.spawn     = definida("SPAWN");
    c.room      = definida("ROOM");
    c.classInfo = definida("CLASSINFO");
    c.enterGame = definida("ENTER_GAME");

    // Grupo 2: jugador y sala.
    c.nombreJugador = texto("PNAME", "Innamine");
    c.idJugador     = static_cast<uint32_t>(entero("PID", 1));
    c.nombreMapa    = texto("MAPNAME", "patio");
    c.plantilla     = static_cast<uint32_t>(entero("TMPL", 1));
    c.idSala        = static_cast<uint32_t>(entero("RID", 1));
    c.mapa          = static_cast<int>(entero("MAP", 0xfa));

    // Grupo 3: lista de prisiones.
    c.listaRica     = definida("RICH_LIST");
    c.nombrePrision = texto("PRISON_NAME", "La Prision");
    c.reclusos      = static_cast<uint32_t>(entero("RECLUSOS", 42));

    // Grupo 4: avanzado / depuración.
    c.tamPosicion = static_cast<int>(entero("POS_SZ", 0x220));
    c.tamDatosJug = static_cast<int>(entero("PD_SZ", 0x220));

    c.tieneStartFieldc = definida("START_FIELDC");
    c.startFieldc      = static_cast<int>(entero("START_FIELDC", 0));

    c.barridoDesde = static_cast<int>(entero("SWEEP_LO", 0x1388));
    c.barridoHasta = static_cast<int>(entero("SWEEP_HI", 0x1480));
    c.barridoMs    = static_cast<int>(entero("SWEEP_MS", 250));

    return c;
}

const Configuracion& cfg() {
    // Se inicializa una sola vez (la primera llamada) y se reutiliza siempre.
    static const Configuracion instancia = cargar();
    return instancia;
}

} // namespace prison
