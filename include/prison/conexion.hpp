// ============================================================================
//  conexion.hpp  —  Estado de UN cliente conectado
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  El protocolo SNS es "UDP fiable": aunque UDP no garantiza entrega, nosotros
//  llevamos cuenta de números de mensaje, secuencia y ACKs por cada cliente.
//  Cada cliente conectado tiene una estructura "Conexion" que guarda TODO su
//  estado: su id asignado, su clave de cifrado, en qué fase del handshake está,
//  qué mensajes ya le hemos enviado, etc.
//
//  Los servidores guardan estas conexiones en un mapa:
//        clave (IP+puerto)  ->  Conexion
//  (ver utilidades.hpp::claveDeConexion)
// ============================================================================
#pragma once

#include <cstdint>
#include <string>

#include "prison/base_datos.hpp"  // struct Cuenta

namespace prison {

// Fase del "handshake" (saludo inicial) de una conexión SNS.
enum class Fase {
    Nueva        = 0,  // recién llegó, aún sin responder
    SynRespondido = 1, // le enviamos el SYN-ACK, esperando su ACK
    Establecida  = 2   // handshake completo, ya puede intercambiar datos
};

struct Conexion {
    uint32_t idConexion = 0;     // id único asignado a esta conexión (no 0xFFFFFFFF)
    uint32_t clave      = 0;     // clave XOR negociada (K) para cifrar/descifrar
    Fase     fase       = Fase::Nueva;
    std::string usuario;         // nombre de usuario recibido en el SYN

    // ---- Contadores de envío fiable (servidor -> cliente) ----
    uint32_t idMensajeTx = 0;    // id del mensaje saliente (campo "field_c"); el cliente lo confirma con ACK
    uint32_t secuenciaTx = 0;    // número de secuencia saliente

    // ---- Banderas: ¿qué pasos del login ya completamos? ----
    bool enviadoLogin   = false; // ¿ya enviamos la estructura de cuenta?
    bool enviadoAceptar = false; // ¿ya enviamos LOGINACCEPTED + lista de servidores?
    bool enviadoEntrar  = false; // ¿ya enviamos ENTERINGGAMEACCEPTED?

    uint32_t idCuenta   = 0;     // id de la cuenta en MySQL (0 si no se encontró)
    Cuenta   cuenta;             // datos de la cuenta (para validar en el LOGIN)
    uint32_t ultimaActividad = 0; // epoch del último paquete recibido (para "cuenta en uso")
    uint32_t prisionSeleccionada = 1; // prisión (game_servers.id) en la que está la cuenta
};

} // namespace prison
