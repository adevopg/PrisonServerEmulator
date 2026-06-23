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
//  CÓMO RECHAZA EL CLIENTE (sacado de Carcelclient.exe por ingeniería inversa):
//
//    - Mensaje de rechazo = opcode de red 0x138a (LOGINREJECTED).
//    - Payload = [codigo:1]  (un solo byte con el motivo).
//    - El cliente admite códigos 0..11 (12 mensajes en su archivo de idioma);
//      cada código muestra un texto distinto. El TEXTO de cada código lo define
//      el archivo de idioma del cliente (no el servidor), así que aquí solo
//      elegimos QUÉ código enviar para cada estado.
//    - El CÓDIGO 7 es especial: además del byte lleva un timestamp (4 bytes)
//      -> se usa para "baneado/espera HASTA una fecha".
//      (Switch del cliente en 0x4a6b00, tabla en 0x4a71d4.)
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
};

// Códigos de rechazo que viajan en LOGINREJECTED (opcode 0x138a, payload[0]).
// El cliente soporta 0..11. El 7 lleva timestamp. El texto de cada código se
// configura en el archivo de idioma del cliente.
namespace rechazo {
    constexpr uint8_t GENERICO      = 0;  // motivo por defecto
    constexpr uint8_t CONTRASENA    = 1;  // contraseña incorrecta
    constexpr uint8_t NO_EXISTE     = 2;  // cuenta inexistente
    constexpr uint8_t SIN_TIEMPO    = 3;  // sin tiempo de juego
    constexpr uint8_t MANTENIMIENTO = 4;  // servidor en mantenimiento
    constexpr uint8_t YA_CONECTADA  = 5;  // sesión ya activa
    constexpr uint8_t BANEADA       = 6;  // baneada permanente
    constexpr uint8_t BANEADA_HASTA = 7;  // baneada hasta fecha (lleva timestamp)  [CONFIRMADO]
    // 8..11: el cliente los admite pero su significado no está confirmado.
}

// Traduce un estado de cuenta al código de rechazo del cliente.
inline uint8_t estadoARechazo(EstadoCuenta estado) {
    switch (estado) {
        case EstadoCuenta::ContrasenaIncorrecta: return rechazo::CONTRASENA;
        case EstadoCuenta::NoExiste:             return rechazo::NO_EXISTE;
        case EstadoCuenta::SinTiempoDeJuego:     return rechazo::SIN_TIEMPO;
        case EstadoCuenta::EnMantenimiento:      return rechazo::MANTENIMIENTO;
        case EstadoCuenta::YaConectada:          return rechazo::YA_CONECTADA;
        case EstadoCuenta::Baneada:              return rechazo::BANEADA;
        case EstadoCuenta::BaneadaTemporal:      return rechazo::BANEADA_HASTA;
        default:                                 return rechazo::GENERICO;
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
        default:                                 return "?";
    }
}

} // namespace prison
