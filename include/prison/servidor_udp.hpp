// ============================================================================
//  servidor_udp.hpp  —  Servidor UDP base usando Boost.Asio
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  Esta es la clase BASE de todos los servidores (login, mundo, updates).
//  Se encarga de toda la parte de RED con la librería Boost.Asio:
//
//      - abrir un socket UDP y "atarlo" (bind) a un puerto
//      - recibir paquetes en un bucle (ejecutar())
//      - enviar paquetes (enviar / enviarFiable / enviarFragmentado)
//
//  Cada servidor concreto HEREDA de esta clase y solo implementa el método
//  "procesarPaquete()", donde decide qué hacer con cada paquete que llega.
//  Así la lógica de cada servidor queda separada y limpia.
//
//  ¿POR QUÉ BOOST.ASIO?
//  Boost.Asio es la librería de red estándar de C++. Nos da un socket UDP
//  portable y robusto (boost::asio::ip::udp::socket) en lugar de usar la API
//  cruda de Windows (Winsock). El código queda más claro y mantenible.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <boost/asio.hpp>

#include "prison/conexion.hpp"

namespace prison {

class ServidorUdp {
public:
    // io        = el "motor" de Boost.Asio (compartido entre servidores)
    // nombre    = etiqueta para los logs (ej: "LOGIN", "MUNDO")
    // puerto    = puerto UDP donde escucha
    ServidorUdp(boost::asio::io_context& io, std::string nombre, uint16_t puerto);
    virtual ~ServidorUdp() = default;

    // Abre el socket y lo ata al puerto. Devuelve true si lo consigue.
    bool iniciar();

    // Bucle principal: recibe paquetes y los pasa a procesarPaquete().
    // (Bloquea; normalmente se lanza en su propio hilo.)
    void ejecutar();

    const std::string& nombre() const { return nombre_; }

protected:
    // -------- Lo implementa cada servidor concreto --------
    // datos  = bytes del paquete recibido
    // n      = longitud del paquete
    // remoto = dirección (IP+puerto) del cliente que lo envió
    virtual void procesarPaquete(uint8_t* datos, int n,
                                 const boost::asio::ip::udp::endpoint& remoto) = 0;

    // -------- Helpers de envío (los usan las clases hijas) --------

    // Envía bytes crudos tal cual al destino.
    void enviar(const uint8_t* datos, int n,
                const boost::asio::ip::udp::endpoint& destino);

    // Envía un mensaje de aplicación FIABLE (servidor -> cliente), cifrado.
    // Construye la cabecera SNS, cifra el payload y lo manda. El cliente lo
    // confirmará con un ACK. "datosPayload" es el payload ya compuesto con
    // protocolo::componerMensajeApp().
    void enviarFiable(Conexion& c, const boost::asio::ip::udp::endpoint& destino,
                      const uint8_t* datosPayload, int longitud);

    // Envía un mensaje grande partido en FRAGMENTOS SNS. El cliente reensambla
    // los fragmentos que comparten un mismo id de mensaje. Se usa para datos
    // grandes (estructura de cuenta, listas comprimidas, etc.).
    void enviarFragmentado(Conexion& c, const boost::asio::ip::udp::endpoint& destino,
                           const uint8_t* datosApp, int n);

    // Contador de "timestamp" que va en cada paquete saliente. Cada servidor
    // tiene el suyo. Se puede inicializar en el constructor de la clase hija.
    uint32_t contadorMarcaTiempo_ = 0x11223344;

private:
    boost::asio::io_context&      io_;
    boost::asio::ip::udp::socket  socket_;
    std::string                   nombre_;
    uint16_t                      puerto_;
};

} // namespace prison
