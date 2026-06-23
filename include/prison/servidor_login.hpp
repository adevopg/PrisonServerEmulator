// ============================================================================
//  servidor_login.hpp  —  Servidor de LOGIN (UDP 25666)
// ============================================================================
//
//  ¿QUÉ HACE?
//
//  Es el primer servidor con el que habla el cliente. Se encarga de:
//      1) Completar el handshake SNS (SYN -> SYN-ACK -> ACK).
//      2) Autenticar la cuenta contra MySQL.
//      3) Enviar la estructura de la cuenta y el/los personaje(s).
//      4) Mostrar la lista de servidores de mundo (selección de "prisión").
//      5) Cuando el jugador pulsa JUGAR, decirle que entre al mundo, tras lo
//         cual el cliente se desconecta de aquí y se conecta al ServidorMundo.
//
//  Toda la lógica byte a byte viene de la ingeniería inversa del cliente; los
//  números de "opcode" (0x1388, 0x1389, ...) son los mensajes del protocolo de
//  aplicación de "La Prisión".
// ============================================================================
#pragma once

#include <cstdint>
#include <map>

#include "prison/servidor_udp.hpp"
#include "prison/conexion.hpp"
#include "prison/base_datos.hpp"

namespace prison {

class ServidorLogin : public ServidorUdp {
public:
    ServidorLogin(boost::asio::io_context& io, BaseDatos& bd);

protected:
    void procesarPaquete(uint8_t* datos, int n,
                         const boost::asio::ip::udp::endpoint& remoto) override;

private:
    // Maneja la fase de DATOS (cuando ya hay handshake): descifra, ACKea y
    // procesa los mensajes de aplicación (login, crear personaje, etc.).
    void procesarDatos(uint8_t* datos, int n,
                       const boost::asio::ip::udp::endpoint& remoto,
                       uint16_t flags, uint16_t secuencia);

    BaseDatos& bd_;

    // Conexiones activas: clave (IP+puerto) -> estado de la conexión.
    std::map<uint64_t, Conexion> conexiones_;

    // Siguiente id de conexión a asignar.
    uint32_t siguienteId_ = 0x10000001;
};

} // namespace prison
