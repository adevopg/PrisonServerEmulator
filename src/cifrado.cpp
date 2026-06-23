// ============================================================================
//  cifrado.cpp  —  Implementación del cifrado XOR y la compresión zlib stored
//                  (ver cifrado.hpp para la explicación de qué hace cada cosa)
// ============================================================================
#include "prison/cifrado.hpp"
#include <cstring>

namespace prison {
namespace cifrado {

// La semilla del encadenado XOR. Sacada por ingeniería inversa del cliente
// (rutina 0x411dd0). El primer byte se mezcla con este valor inicial.
static const uint8_t SEMILLA = 0x3b;

void descifrar(uint8_t* payload, int n, uint32_t clave) {
    // La clave de 32 bits se usa como 4 bytes independientes (k[0..3]).
    uint8_t k[4] = {
        static_cast<uint8_t>(clave),
        static_cast<uint8_t>(clave >> 8),
        static_cast<uint8_t>(clave >> 16),
        static_cast<uint8_t>(clave >> 24)
    };

    uint8_t anterior = SEMILLA;
    for (int i = 0; i < n; i++) {
        uint8_t cifrado = payload[i];
        // descifrado = byteClave ^ cifrado ^ posición ^ byteAnterior
        uint8_t claro = static_cast<uint8_t>(
            k[(i >> 2) & 3] ^ cifrado ^ static_cast<uint8_t>(i) ^ anterior);
        payload[i] = claro;
        // Al DESCIFRAR, el encadenado usa el byte CIFRADO (el que llegó).
        anterior = cifrado;
    }
}

void cifrar(uint8_t* payload, int n, uint32_t clave) {
    uint8_t k[4] = {
        static_cast<uint8_t>(clave),
        static_cast<uint8_t>(clave >> 8),
        static_cast<uint8_t>(clave >> 16),
        static_cast<uint8_t>(clave >> 24)
    };

    uint8_t anterior = SEMILLA;
    for (int i = 0; i < n; i++) {
        uint8_t salida = static_cast<uint8_t>(
            k[(i >> 2) & 3] ^ payload[i] ^ static_cast<uint8_t>(i) ^ anterior);
        payload[i] = salida;
        // Al CIFRAR, el encadenado usa el byte de SALIDA (el que enviamos).
        anterior = salida;
    }
}

uint32_t adler32(const uint8_t* datos, int n) {
    uint32_t a = 1, b = 0;
    for (int i = 0; i < n; i++) {
        a = (a + datos[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

int comprimirZlibStored(uint8_t* salida, const uint8_t* entrada, int n) {
    int o = 0;

    // Cabecera zlib de 2 bytes (CMF/FLG, nivel 0 = sin compresión real).
    salida[o++] = 0x78;
    salida[o++] = 0x01;

    // Datos en uno o más bloques "stored" (almacenados tal cual). Cada bloque
    // puede llevar como máximo 0xFFFF bytes.
    int pos = 0;
    do {
        int trozo = n - pos;
        if (trozo > 0xFFFF) trozo = 0xFFFF;
        bool ultimo = (pos + trozo >= n);

        salida[o++] = static_cast<uint8_t>(ultimo ? 1 : 0);          // BFINAL + BTYPE=00
        salida[o++] = static_cast<uint8_t>(trozo & 0xff);           // LEN (bajo)
        salida[o++] = static_cast<uint8_t>(trozo >> 8);             // LEN (alto)
        salida[o++] = static_cast<uint8_t>(~trozo & 0xff);          // NLEN (~LEN)
        salida[o++] = static_cast<uint8_t>((~trozo >> 8) & 0xff);
        if (trozo) {
            memcpy(salida + o, entrada + pos, trozo);
            o += trozo;
        }
        pos += trozo;
    } while (pos < n);

    // Checksum Adler-32 al final, en formato big-endian (byte más alto primero).
    uint32_t ad = adler32(entrada, n);
    salida[o++] = static_cast<uint8_t>(ad >> 24);
    salida[o++] = static_cast<uint8_t>(ad >> 16);
    salida[o++] = static_cast<uint8_t>(ad >> 8);
    salida[o++] = static_cast<uint8_t>(ad & 0xff);

    return o;
}

} // namespace cifrado
} // namespace prison
