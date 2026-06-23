// ============================================================================
//  estados_cuenta.hpp  —  Estados de una cuenta al iniciar sesión
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  Cuando un jugador intenta iniciar sesión, la cuenta puede estar en varios
//  ESTADOS: correcta, contraseña incorrecta, baneada, sin tiempo de juego,
//  el servidor en mantenimiento, etc. Aquí están todos esos estados en un enum
//  y la traducción de cada estado al CÓDIGO DE RECHAZO que entiende el cliente.
//
//  ─────────────────────────────────────────────────────────────────────────
//  CÓMO RECHAZA EL CLIENTE (confirmado por ingeniería inversa de Carcelclient):
//
//    - Mensaje de rechazo = opcode de red 0x138a (LOGINREJECTED), payload [codigo:1].
//    - El cliente usa el código como índice en su tabla de mensajes: el switch
//      en 0x4a6b00 lee msg[ [0x5edff4] + codigo->offset ]; cada offset = ID de
//      mensaje x 4. Los textos están en Data\Config\languages\ES_Lan_Messages.txt.
//    - MAPEO REAL código -> mensaje (ID en ES_Lan_Messages.txt):
//        1  -> 1546  DATOS INCORRECTOS (login/password/PIN)
//        2  -> 1547  CUENTA EN USO
//        3  -> 1548  TIEMPO DE JUEGO AGOTADO
//        4  -> 1570  ACTUALIZACION REQUERIDA
//        5  -> 1571  SERVIDOR EN MANTENIMIENTO
//        6  -> 1572  BLOQUEO DE REGION
//        7  -> (fecha) BAN/espera HASTA una fecha  (lleva timestamp de 4 bytes)
//        8  -> 1573  CONEXION RECHAZADA (desde esta conexión a Internet)
//        9  -> 1574  CONEXION RECHAZADA (cuenta avanzada)
//        10 -> 1575  CUENTA EN MANTENIMIENTO
//        11 -> 1845  SERVIDOR COMPLETO
//  ─────────────────────────────────────────────────────────────────────────
// ============================================================================
#pragma once

#include <cstdint>

namespace prison {

// Estado de la cuenta tras comprobarla (dominio del servidor).
enum class EstadoCuenta {
    Ok,                     // todo correcto -> puede iniciar sesión
    NoExiste,               // el usuario no existe en la base de datos
    ContrasenaIncorrecta,   // la contraseña no coincide
    Baneada,                // baneada de forma permanente
    BaneadaTemporal,        // baneada hasta una fecha (lleva timestamp)
    SinTiempoDeJuego,       // sin tiempo / suscripción caducada
    EnMantenimiento,        // el servidor está en mantenimiento
    YaConectada,            // ya hay una sesión activa con esta cuenta
    RecienCreada,           // creada hace < 5 min: aún no reconocida (espere)
};

// Códigos de rechazo de LOGINREJECTED (opcode 0x138a, payload[0]). Cada uno
// muestra el mensaje indicado arriba. (El 7 lleva además un timestamp.)
namespace rechazo {
    constexpr uint8_t DATOS_INCORRECTOS  = 1;  // login/password/PIN incorrectos
    constexpr uint8_t CUENTA_EN_USO      = 2;  // ya hay una sesión activa
    constexpr uint8_t TIEMPO_AGOTADO     = 3;  // sin tiempo de juego / suscripción
    constexpr uint8_t ACTUALIZACION      = 4;  // hace falta actualizar el cliente
    constexpr uint8_t SERVIDOR_MANTEN    = 5;  // servidor en mantenimiento
    constexpr uint8_t BLOQUEO_REGION     = 6;  // bloqueo por país/región
    constexpr uint8_t BANEADA_HASTA      = 7;  // ban/espera hasta fecha (lleva timestamp)
    constexpr uint8_t CONEXION_RECHAZADA = 8;  // conexión no aceptada (IP/red)
    constexpr uint8_t CUENTA_AVANZADA    = 9;  // cuenta avanzada desde esta conexión
    constexpr uint8_t CUENTA_MANTEN      = 10; // cuenta en mantenimiento / no accesible
    constexpr uint8_t SERVIDOR_COMPLETO  = 11; // servidor lleno
}

// Traduce un estado de cuenta al código de rechazo del cliente.
inline uint8_t estadoARechazo(EstadoCuenta estado) {
    switch (estado) {
        // "No existe" y "contraseña incorrecta" muestran el MISMO mensaje
        // (DATOS INCORRECTOS): así no se revela si la cuenta existe o no.
        case EstadoCuenta::ContrasenaIncorrecta: return rechazo::DATOS_INCORRECTOS;
        case EstadoCuenta::NoExiste:             return rechazo::DATOS_INCORRECTOS;
        case EstadoCuenta::YaConectada:          return rechazo::CUENTA_EN_USO;
        case EstadoCuenta::SinTiempoDeJuego:     return rechazo::TIEMPO_AGOTADO;
        case EstadoCuenta::EnMantenimiento:      return rechazo::SERVIDOR_MANTEN;
        case EstadoCuenta::Baneada:              return rechazo::CUENTA_MANTEN;   // no hay msg "baneado"; "cuenta no accesible" es lo más cercano
        case EstadoCuenta::BaneadaTemporal:      return rechazo::BANEADA_HASTA;   // lleva timestamp
        // Recién creada: el mensaje DATOS INCORRECTOS ya dice "si acaba de crear
        // la cuenta, espere unos minutos".
        case EstadoCuenta::RecienCreada:         return rechazo::DATOS_INCORRECTOS;
        default:                                 return rechazo::DATOS_INCORRECTOS;
    }
}

// Texto corto del estado para los logs del servidor.
inline const char* nombreEstado(EstadoCuenta estado) {
    switch (estado) {
        case EstadoCuenta::Ok:                   return "OK";
        case EstadoCuenta::NoExiste:             return "NO EXISTE";
        case EstadoCuenta::ContrasenaIncorrecta: return "CONTRASEÑA INCORRECTA";
        case EstadoCuenta::Baneada:              return "BANEADA";
        case EstadoCuenta::BaneadaTemporal:      return "BANEADA TEMPORALMENTE";
        case EstadoCuenta::SinTiempoDeJuego:     return "SIN TIEMPO DE JUEGO";
        case EstadoCuenta::EnMantenimiento:      return "EN MANTENIMIENTO";
        case EstadoCuenta::YaConectada:          return "YA CONECTADA";
        case EstadoCuenta::RecienCreada:         return "RECIÉN CREADA (espera 5 min)";
        default:                                 return "?";
    }
}

} // namespace prison
