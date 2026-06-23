// ============================================================================
//  base_datos.hpp  —  Acceso a la base de datos MySQL
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  Toda la comunicación con MySQL (la base de datos "prison") está AQUÍ, en un
//  solo sitio, para que el resto del servidor no tenga que saber nada de SQL.
//
//  La base de datos guarda:
//      - accounts       : las cuentas de los jugadores (login)
//      - characters     : los personajes
//      - game_servers   : la lista de servidores de mundo que ve el jugador
//
//  Datos de conexión (definidos en el .cpp):
//      host=127.0.0.1  usuario=Inna  contraseña=Ladyamy89  base=prison
//
//  Uso:
//      BaseDatos bd;
//      if (bd.conectar()) { ... }
//      auto cuenta = bd.buscarCuenta("innapmine");
//      auto servidores = bd.listarServidores();
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Adelantamos el tipo de MySQL para no incluir <mysql.h> en la cabecera
// (así quien use base_datos.hpp no necesita los headers de MySQL).
struct MYSQL;

namespace prison {

// Resultado de buscar una cuenta por nombre de usuario.
struct Cuenta {
    bool        encontrada = false;
    uint32_t    id         = 0;
    uint32_t    nivelGm    = 0;       // 0 = jugador normal, >0 = GameMaster
    bool        baneada    = false;   // ban permanente (columna 'banned')
    std::string hashContrasena;       // hash que esperamos del cliente (hex), vacío = no validar
    uint32_t    baneadaHasta   = 0;   // epoch del ban temporal (0 = sin ban temporal)
    uint32_t    suscripcionHasta = 0; // epoch de fin de suscripción (0 = ilimitada)
};

// Una "prisión" (servidor de mundo) de la lista de selección. Los campos son
// EXACTAMENTE los que el cliente lee en SERVERADDED (0x13a9) y AVAILABLESERVERS
// (0x13ac): id, flag, extra, nombre, nombre2 (se muestra "nombre nombre2") y la
// población ("reclusos").
struct ServidorJuego {
    uint32_t    id        = 0;   // id de la prisión
    std::string nombre;          // nombre mostrado
    std::string nombre2;         // segundo texto (el cliente muestra "nombre nombre2")
    uint8_t     flag      = 2;   // byte que el cliente guarda en el nodo (por defecto 2)
    uint32_t    extra     = 0;   // dword extra que el cliente guarda en el nodo
    uint32_t    poblacion = 0;   // "reclusos" conectados
};

class BaseDatos {
public:
    BaseDatos() = default;
    ~BaseDatos();

    // Conecta a MySQL. Devuelve true si lo consigue.
    bool conectar();

    // ¿Estamos conectados?
    bool estaConectada() const { return mysql_ != nullptr; }

    // Texto del último error de MySQL (para registrarlo).
    const char* ultimoError() const;

    // Busca una cuenta por su nombre de usuario.
    Cuenta buscarCuenta(const std::string& usuario);

    // Devuelve TODAS las prisiones/servidores en línea (ordenadas por sort_order).
    std::vector<ServidorJuego> listarServidores();

    // ---- Personajes ----

    // Cuántos personajes (no borrados) tiene la cuenta.
    int contarPersonajes(uint32_t idCuenta);

    // Guarda un personaje nuevo. "datos" es el bloque crudo de aspecto/atributos
    // que envía el cliente (puede ser nullptr). Devuelve true si se insertó.
    bool crearPersonaje(uint32_t idCuenta, int slot, const std::string& nick,
                        const uint8_t* datos, int longitudDatos);

private:
    MYSQL* mysql_ = nullptr;
};

} // namespace prison
