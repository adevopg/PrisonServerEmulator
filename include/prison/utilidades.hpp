// ============================================================================
//  utilidades.hpp  —  Funciones pequeñas para leer/escribir números en la red
// ============================================================================
//
//  ¿PARA QUÉ SIRVE ESTE ARCHIVO?
//
//  El cliente "Carcelclient.exe" envía los números (enteros de 16 y 32 bits)
//  en orden "little-endian": el byte menos significativo va primero.
//  Estas funciones convierten entre:
//
//      bytes en el paquete  <-->  números que entiende el programa
//
//  Se usan EN TODOS LADOS, así que están aquí para no repetir código.
//
//      leer16 / leer32   ->  lee un número desde un puntero a bytes
//      escribir16/32     ->  escribe un número dentro de un buffer de bytes
//
//  También está "claveDeConexion", que convierte la dirección (IP + puerto)
//  de un cliente en un número único, para usarlo como clave en los mapas de
//  conexiones (cada cliente tiene su propio estado).
// ============================================================================
#pragma once

#include <cstdint>
#include <boost/asio.hpp>

namespace prison {

// ---- LEER números desde un buffer de bytes (formato de la red, little-endian) ----

inline uint16_t leer16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

inline uint32_t leer32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) |
                                (static_cast<uint32_t>(p[3]) << 24));
}

// ---- ESCRIBIR números dentro de un buffer de bytes ----

inline void escribir16(uint8_t* p, uint16_t valor) {
    p[0] = static_cast<uint8_t>(valor);
    p[1] = static_cast<uint8_t>(valor >> 8);
}

inline void escribir32(uint8_t* p, uint32_t valor) {
    p[0] = static_cast<uint8_t>(valor);
    p[1] = static_cast<uint8_t>(valor >> 8);
    p[2] = static_cast<uint8_t>(valor >> 16);
    p[3] = static_cast<uint8_t>(valor >> 24);
}

// ----------------------------------------------------------------------------
//  claveDeConexion: identifica de forma única a un cliente por su IP + puerto.
//
//  Boost.Asio nos da la dirección del cliente en un "endpoint". Combinamos la
//  IP (32 bits) y el puerto (16 bits) en un solo número de 64 bits que usamos
//  como clave en el mapa de conexiones (ver conexion.hpp).
// ----------------------------------------------------------------------------
inline uint64_t claveDeConexion(const boost::asio::ip::udp::endpoint& remoto) {
    uint32_t ip = remoto.address().to_v4().to_uint();
    uint16_t puerto = remoto.port();
    return (static_cast<uint64_t>(ip) << 16) | puerto;
}

} // namespace prison
