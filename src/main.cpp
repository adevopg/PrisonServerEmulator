// ============================================================================
//  main.cpp  —  Punto de entrada del PrisonServer
// ============================================================================
//
//  ¿QUÉ HACE?
//
//  Arranca los tres servidores del juego "La Prisión":
//
//      - ServidorLogin   (UDP 25666) -> autenticación y selección de servidor
//      - ServidorUpdates (UDP 25667) -> actualizaciones (solo escucha/registra)
//      - ServidorMundo   (UDP 25001) -> el juego en sí
//
//  Cada servidor corre en su propio HILO, pero todos comparten un único
//  "io_context" de Boost.Asio (el motor de red). El hilo principal se queda con
//  el servidor de login.
//
//  Pasos:
//      1) Conectar a MySQL.
//      2) Iniciar (abrir+atar) los tres servidores.
//      3) Lanzar cada servidor en su hilo.
// ============================================================================
#include "prison/registro.hpp"
#include "prison/base_datos.hpp"
#include "prison/servidor_login.hpp"
#include "prison/servidor_mundo.hpp"
#include "prison/servidor_updates.hpp"

#include <boost/asio.hpp>
#include <thread>

int main() {
    using namespace prison;

    // Abrir el archivo de log.
    registro::abrir("login_server.log");

    // 1) Conectar a la base de datos.
    BaseDatos bd;
    if (bd.conectar())
        registro::log("MySQL conectado (base 'prison', usuario Inna)");
    else
        registro::log("MySQL FALLÓ al conectar: %s", bd.ultimoError());

    // El "motor" de Boost.Asio, compartido por todos los servidores.
    boost::asio::io_context io;

    // 2) Crear e iniciar los tres servidores.
    ServidorLogin   login(io, bd);
    ServidorUpdates updates(io);
    ServidorMundo   mundo(io);

    if (!login.iniciar())   return 1;
    updates.iniciar();   // si falla, seguimos igual (no es crítico)
    mundo.iniciar();

    // 3) Cada servidor en su propio hilo. El login se queda en el hilo principal.
    std::thread hiloUpdates([&] { updates.ejecutar(); });
    std::thread hiloMundo([&]   { mundo.ejecutar(); });

    login.ejecutar();   // bloquea aquí para siempre

    hiloUpdates.join();
    hiloMundo.join();
    registro::cerrar();
    return 0;
}
