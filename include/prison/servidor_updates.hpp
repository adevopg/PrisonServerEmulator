// ============================================================================
//  servidor_updates.hpp  —  Servidor de ACTUALIZACIONES (UDP 25667)
// ============================================================================
//
//  ¿QUÉ HACE?
//
//  El cliente puede contactar este servidor para buscar parches/actualizaciones.
//  En la práctica el cliente usa HTTP bajo demanda y NO contacta aquí al
//  arrancar, pero escuchamos igualmente y registramos lo que llegue (útil para
//  ingeniería inversa). Por eso este servidor solo recibe y hace log.
// ============================================================================
#pragma once

#include "prison/servidor_udp.hpp"

namespace prison {

class ServidorUpdates : public ServidorUdp {
public:
    explicit ServidorUpdates(boost::asio::io_context& io);

protected:
    void procesarPaquete(uint8_t* datos, int n,
                         const boost::asio::ip::udp::endpoint& remoto) override;
};

} // namespace prison
