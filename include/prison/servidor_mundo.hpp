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
#include <vector>

#include "prison/servidor_udp.hpp"
#include "prison/conexion.hpp"

namespace prison {

class ServidorMundo : public ServidorUdp {
public:
    explicit ServidorMundo(boost::asio::io_context& io);

    // Construye, UNA sola vez al arrancar, el contenido estatico del mundo
    // (de momento el OBJECTINFO) y lo deja cacheado. Registra los tamanos
    // (igual que el servidor original: "Compressed Objectinfo size ...").
    void prepararContenido();

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

    // Tablas de sala ya construidas (opcode + tamanos + zlib), listas para
    // enviar a cada cliente. Se rellenan en prepararContenido().
    std::vector<uint8_t> objInfo_;       // OBJECTSINFO (0x13a8) con los objetos
    std::vector<uint8_t> botsInfo_;      // BOTSINFO   (0x13a7) tabla vacia (0 NPCs)
    std::vector<uint8_t> suppliesInfo_;  // SUPPLIESINFO (0x13a6) tabla vacia (0 supplies)
    std::vector<uint8_t> questsInfo_;    // QUESTSINFO (0x14ee) tabla vacia (0 misiones)
    std::vector<uint8_t> boxesInfo_;     // BOXESINFO  (0x13a4) vacia (compSize=0 -> limpia)
};

} // namespace prison
