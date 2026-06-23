// ============================================================================
//  servidor_mundo.hpp  —  Servidor de MUNDO / juego (UDP 25001)
// ============================================================================
//
//  ¿QUÉ HACE?
//
//  Después de pulsar JUGAR, el cliente se desconecta del login y se conecta
//  AQUÍ (al "mundo"). Usa el mismo transporte SNS. Este servidor:
//
//      1) Completa el handshake SNS (igual que el login).
//      2) Responde al PING del cliente (PONG) para mantener viva la conexión
//         (si no, el cliente muestra "CONEXION INTERRUMPIDA" y se cae).
//      3) (Experimental) Hace aparecer al jugador en el mapa (SPAWN) y envía
//         la configuración de sala/mapa/objetos cuando el cliente lo pide.
//
//  La mayoría de la lógica de aparición está controlada por variables de
//  entorno (SPAWN, ROOM, etc.) porque sigue en fase de ingeniería inversa.
// ============================================================================
#pragma once

#include <cstdint>
#include <map>

#include "prison/servidor_udp.hpp"
#include "prison/conexion.hpp"

namespace prison {

class ServidorMundo : public ServidorUdp {
public:
    explicit ServidorMundo(boost::asio::io_context& io);

protected:
    void procesarPaquete(uint8_t* datos, int n,
                         const boost::asio::ip::udp::endpoint& remoto) override;

private:
    // Procesa la fase de datos: PONG y, opcionalmente, la aparición del jugador.
    void procesarDatos(uint8_t* datos, int n,
                       const boost::asio::ip::udp::endpoint& remoto,
                       uint16_t flags, uint16_t opcode);

    std::map<uint64_t, Conexion> conexiones_;
    uint32_t siguienteId_ = 0x20000001;
};

} // namespace prison
