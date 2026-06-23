// ============================================================================
//  servidor_updates.cpp  —  Implementación del servidor de actualizaciones
// ============================================================================
#include "prison/servidor_updates.hpp"
#include "prison/protocolo_sns.hpp"
#include "prison/registro.hpp"

namespace prison {

using boost::asio::ip::udp;

ServidorUpdates::ServidorUpdates(boost::asio::io_context& io)
    : ServidorUdp(io, "UPDATES", protocolo::PUERTO_UPDATES) {}

void ServidorUpdates::procesarPaquete(uint8_t* datos, int n, const udp::endpoint& remoto) {
    std::string ip = remoto.address().to_string();
    registro::log("[UPDATES] <- %s:%u len=%d", ip.c_str(), remoto.port(), n);
    registro::volcadoHex("   upd:", datos, n > 64 ? 64 : n);
}

} // namespace prison
