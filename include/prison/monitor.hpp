// ============================================================================
//  monitor.hpp  —  Estado compartido entre los servidores y la ventana (GUI)
// ============================================================================
//
//  La GUI (ventana del servidor) y los servidores corren en HILOS distintos.
//  Este modulo guarda, de forma segura entre hilos, lo que la ventana necesita
//  mostrar: las lineas de log (consola), el numero de clientes y la lista de
//  jugadores conectados. Los servidores ESCRIBEN aqui; la GUI LEE cada segundo.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace prison {
namespace monitor {

// ---- LOG (consola de la GUI) ----
// registro::log() llama a esto por cada linea; la GUI las saca con drenarLog().
void emitirLog(const std::string& linea);
void drenarLog(std::vector<std::string>& salida);   // mueve las pendientes a 'salida'

// ---- JUGADORES / CLIENTES ----
struct Jugador {
    uint64_t    clave = 0;     // identificador de conexion
    std::string nick;          // nombre mostrado
    std::string sala;          // sala/zona
    int         ping = 0;      // ms
    long long   t0   = 0;      // epoch (segundos) de conexion -> "Time Online"
};

void clienteEntra(uint64_t clave, const std::string& nick, const std::string& sala);
void clienteSala(uint64_t clave, const std::string& sala);
void clientePing(uint64_t clave, int ping);
void clienteSale(uint64_t clave);

std::vector<Jugador> jugadores();   // copia para la GUI
int numClientes();                  // jugadores activos
int picoClientes();                 // maximo historico

} // namespace monitor
} // namespace prison
