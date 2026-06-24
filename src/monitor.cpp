// ============================================================================
//  monitor.cpp  —  Implementacion del estado compartido (ver monitor.hpp)
// ============================================================================
#include "prison/monitor.hpp"

#include <deque>
#include <mutex>
#include <ctime>

namespace prison {
namespace monitor {

namespace {
    std::mutex             mtx;
    std::deque<std::string> colaLog;     // lineas de log pendientes de mostrar
    std::vector<Jugador>   jugs;          // jugadores activos
    int                    pico = 0;      // pico de clientes

    long long ahora() { return (long long)::time(nullptr); }
}

void emitirLog(const std::string& linea) {
    std::lock_guard<std::mutex> lk(mtx);
    colaLog.push_back(linea);
    // No dejar crecer sin limite si la GUI aun no drena.
    if (colaLog.size() > 5000) colaLog.pop_front();
}

void drenarLog(std::vector<std::string>& salida) {
    std::lock_guard<std::mutex> lk(mtx);
    salida.assign(colaLog.begin(), colaLog.end());
    colaLog.clear();
}

void clienteEntra(uint64_t clave, uint32_t idServidor, const std::string& nick, const std::string& sala) {
    std::lock_guard<std::mutex> lk(mtx);
    for (auto& j : jugs) if (j.clave == clave) { j.idServidor = idServidor; j.nick = nick; j.sala = sala; return; }
    Jugador j; j.clave = clave; j.idServidor = idServidor; j.nick = nick; j.sala = sala; j.t0 = ahora();
    jugs.push_back(j);
    if ((int)jugs.size() > pico) pico = (int)jugs.size();
}

void clienteSala(uint64_t clave, const std::string& sala) {
    std::lock_guard<std::mutex> lk(mtx);
    for (auto& j : jugs) if (j.clave == clave) { j.sala = sala; return; }
}

void clientePing(uint64_t clave, int ping) {
    std::lock_guard<std::mutex> lk(mtx);
    for (auto& j : jugs) if (j.clave == clave) { j.ping = ping; return; }
}

void clienteSale(uint64_t clave) {
    std::lock_guard<std::mutex> lk(mtx);
    for (size_t i = 0; i < jugs.size(); i++)
        if (jugs[i].clave == clave) { jugs.erase(jugs.begin() + i); return; }
}

std::vector<Jugador> jugadores() {
    std::lock_guard<std::mutex> lk(mtx);
    return jugs;
}

int numClientes() { std::lock_guard<std::mutex> lk(mtx); return (int)jugs.size(); }
int picoClientes() { std::lock_guard<std::mutex> lk(mtx); return pico; }

} // namespace monitor
} // namespace prison
