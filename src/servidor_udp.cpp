// ============================================================================
//  servidor_udp.cpp  —  Implementación del servidor UDP base (ver servidor_udp.hpp)
// ============================================================================
#include "prison/servidor_udp.hpp"
#include "prison/protocolo_sns.hpp"
#include "prison/cifrado.hpp"
#include "prison/utilidades.hpp"
#include "prison/registro.hpp"

#include <cstring>

namespace prison {

using boost::asio::ip::udp;

ServidorUdp::ServidorUdp(boost::asio::io_context& io, std::string nombre, uint16_t puerto)
    : io_(io), socket_(io), nombre_(std::move(nombre)), puerto_(puerto) {}

bool ServidorUdp::iniciar() {
    boost::system::error_code ec;

    // Abrir el socket UDP (IPv4).
    socket_.open(udp::v4(), ec);
    if (ec) {
        registro::log("[%s] No se pudo abrir el socket: %s",
                      nombre_.c_str(), ec.message().c_str());
        return false;
    }

    // Atar (bind) el socket a "todas las interfaces" en nuestro puerto.
    socket_.bind(udp::endpoint(udp::v4(), puerto_), ec);
    if (ec) {
        registro::log("[%s] No se pudo atar al puerto %u: %s",
                      nombre_.c_str(), puerto_, ec.message().c_str());
        return false;
    }

    registro::log("==== Servidor %s escuchando UDP 0.0.0.0:%u ====",
                  nombre_.c_str(), puerto_);
    return true;
}

void ServidorUdp::ejecutar() {
    uint8_t buffer[65536];
    udp::endpoint remoto;

    for (;;) {
        boost::system::error_code ec;
        // Recibir un paquete (bloquea hasta que llegue uno).
        std::size_t n = socket_.receive_from(boost::asio::buffer(buffer), remoto, 0, ec);
        if (ec) {
            registro::log("[%s] Error al recibir: %s", nombre_.c_str(), ec.message().c_str());
            continue;
        }
        // Entregar el paquete al servidor concreto.
        procesarPaquete(buffer, static_cast<int>(n), remoto);
    }
}

void ServidorUdp::enviar(const uint8_t* datos, int n, const udp::endpoint& destino) {
    boost::system::error_code ec;
    socket_.send_to(boost::asio::buffer(datos, n), destino, 0, ec);
    if (ec) {
        registro::log("[%s] Error al enviar: %s", nombre_.c_str(), ec.message().c_str());
    }
}

void ServidorUdp::enviarFiable(Conexion& c, const udp::endpoint& destino,
                               const uint8_t* datosPayload, int longitud) {
    static uint8_t paquete[16384];
    memset(paquete, 0, protocolo::TAM_CABECERA + longitud);

    // --- Cabecera SNS (22 bytes) ---
    escribir32(paquete + protocolo::OFF_CONN_LO, 0x00000001u);           // connLo (no 0xFF)
    escribir32(paquete + protocolo::OFF_CONN_HI, c.idConexion);          // connHi = id asignado
    escribir16(paquete + protocolo::OFF_FLAGS,
               protocolo::FLAG_PIDE_ACK | protocolo::FLAG_LLEVA_DATOS);  // pide-ACK + lleva-datos
    paquete[protocolo::OFF_VENTANA] = 1;                                 // ventana
    paquete[protocolo::OFF_ACK]     = 0;                                 // ack
    escribir32(paquete + protocolo::OFF_CAMPO_C, ++c.idMensajeTx);       // id de mensaje (el cliente lo ACKea)
    escribir32(paquete + protocolo::OFF_MARCA_TIEMPO, ++contadorMarcaTiempo_);
    escribir16(paquete + protocolo::OFF_SECUENCIA, static_cast<uint16_t>(c.secuenciaTx));

    // --- Payload (cifrado) ---
    memcpy(paquete + protocolo::OFF_PAYLOAD, datosPayload, longitud);
    cifrado::cifrar(paquete + protocolo::OFF_PAYLOAD, longitud, c.clave);

    int total = protocolo::TAM_CABECERA + longitud;
    enviar(paquete, total, destino);

    registro::log("   => enviarFiable idMensaje=%u longitud=%d", c.idMensajeTx, longitud);
}

void ServidorUdp::enviarFragmentado(Conexion& c, const udp::endpoint& destino,
                                    const uint8_t* datosApp, int n) {
    // La ruta multi-fragmento entrega los datos reensamblados TAL CUAL (sin la
    // estructura de registros): M = datosApp directamente ([opcode][datos]).
    // Cada fragmento = [idConexion:4][1:4][trozo].
    const uint8_t* M = datosApp;
    int longM = n;

    const int TROZO = 0x200;                          // datos por fragmento
    int numFrag = (longM + TROZO - 1) / TROZO;
    if (numFrag < 1) numFrag = 1;

    uint32_t base = c.idMensajeTx + 1;                // ids de los fragmentos: base..base+N-1

    for (int i = 0; i < numFrag; i++) {
        int offset = i * TROZO;
        int trozoLen = longM - offset;
        if (trozoLen > TROZO) trozoLen = TROZO;

        static uint8_t paquete[2048];
        memset(paquete, 0, protocolo::TAM_CABECERA + 8 + trozoLen);

        escribir32(paquete + protocolo::OFF_CONN_LO, 0x00000001u);
        escribir32(paquete + protocolo::OFF_CONN_HI, c.idConexion);
        escribir16(paquete + protocolo::OFF_FLAGS,
                   protocolo::FLAG_PIDE_ACK | protocolo::FLAG_LLEVA_DATOS);
        paquete[protocolo::OFF_VENTANA] = static_cast<uint8_t>(numFrag); // ventana = nº de fragmentos
        paquete[protocolo::OFF_ACK]     = static_cast<uint8_t>(i);       // ack = índice del fragmento
        escribir32(paquete + protocolo::OFF_CAMPO_C, ++c.idMensajeTx);   // id incrementa por fragmento
        escribir32(paquete + protocolo::OFF_MARCA_TIEMPO, ++contadorMarcaTiempo_);
        escribir16(paquete + protocolo::OFF_SECUENCIA, static_cast<uint16_t>(c.secuenciaTx));

        // payload = [idConexion][1][trozo]
        escribir32(paquete + protocolo::OFF_PAYLOAD + 0, c.idConexion);
        escribir32(paquete + protocolo::OFF_PAYLOAD + 4, 1);
        memcpy(paquete + protocolo::OFF_PAYLOAD + 8, M + offset, trozoLen);

        int payLen = 8 + trozoLen;
        cifrado::cifrar(paquete + protocolo::OFF_PAYLOAD, payLen, c.clave);
        enviar(paquete, protocolo::TAM_CABECERA + payLen, destino);
    }

    registro::log("   => enviarFragmentado base=%u %d fragmentos (M=%d bytes)",
                  base, numFrag, longM);
}

} // namespace prison
