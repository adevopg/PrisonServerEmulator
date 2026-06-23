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

// Un servidor de mundo de la lista de selección.
struct ServidorJuego {
    uint32_t    id         = 0;
    std::string nombre;
    uint32_t    poblacion  = 0; // "reclusos" conectados
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

    // Devuelve los servidores de mundo en línea (máximo "limite").
    std::vector<ServidorJuego> listarServidores(int limite = 2);

private:
    MYSQL* mysql_ = nullptr;
};

} // namespace prison
