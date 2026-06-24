// ============================================================================
//  cifrado.cpp  —  Implementación del cifrado XOR y la compresión zlib stored
//                  (ver cifrado.hpp para la explicación de qué hace cada cosa)
// ============================================================================
#include "prison/cifrado.hpp"
#include <cstring>
#include <vector>

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

// ============================================================================
//  COMPRESIÓN ZLIB REAL  (DEFLATE: LZ77 + Huffman fijo, BTYPE=01)
//
//  Produce un único bloque DEFLATE con árbol de Huffman FIJO (el estándar de
//  RFC 1951), precedido de la cabecera zlib (0x78 0x01) y seguido del Adler-32.
//  El inflate del cliente lo descomprime exactamente igual que cualquier zlib.
//
//  Reglas de empaquetado de bits (RFC 1951):
//    - los bits se colocan en el byte empezando por el menos significativo.
//    - los códigos de Huffman se escriben empezando por su bit MÁS significativo
//      (por eso se invierten antes de meterlos en el flujo LSB-first).
//    - los "bits extra" de longitud/distancia van LSB-first (sin invertir).
// ============================================================================
namespace {

// Tablas estándar de longitud (códigos 257..285) y distancia (códigos 0..29).
const int LBASE[29]  = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
const int LEXTRA[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
const int DBASE[30]  = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
const int DEXTRA[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

// Escritor de bits LSB-first.
struct EscritorBits {
    uint8_t* out; int o; uint32_t buf; int cnt;
    EscritorBits(uint8_t* p, int inicio) : out(p), o(inicio), buf(0), cnt(0) {}
    void put(uint32_t bits, int n) {
        buf |= (bits << cnt); cnt += n;
        while (cnt >= 8) { out[o++] = (uint8_t)(buf & 0xff); buf >>= 8; cnt -= 8; }
    }
    void flush() { if (cnt > 0) { out[o++] = (uint8_t)(buf & 0xff); buf = 0; cnt = 0; } }
};

// Invierte los n bits de menos peso de v (para escribir códigos MSB-first).
inline uint32_t invertir(uint32_t v, int n) {
    uint32_t r = 0;
    for (int i = 0; i < n; i++) { r = (r << 1) | (v & 1); v >>= 1; }
    return r;
}

// Emite un símbolo literal/longitud con el árbol de Huffman FIJO.
inline void emitirSimbolo(EscritorBits& b, int sym) {
    if      (sym <= 143) b.put(invertir(0x30  + sym,         8), 8);  // 0..143  -> 8 bits
    else if (sym <= 255) b.put(invertir(0x190 + (sym - 144), 9), 9);  // 144..255-> 9 bits
    else if (sym <= 279) b.put(invertir(0x00  + (sym - 256), 7), 7);  // 256..279-> 7 bits
    else                 b.put(invertir(0xC0  + (sym - 280), 8), 8);  // 280..287-> 8 bits
}

inline int indiceLongitud(int len) {                 // len 3..258 -> 0..28
    int i = 28; while (i > 0 && LBASE[i] > len) i--; return i;
}
inline int indiceDistancia(int dist) {               // dist 1..32768 -> 0..29
    int i = 29; while (i > 0 && DBASE[i] > dist) i--; return i;
}

} // namespace

int comprimirZlib(uint8_t* salida, const uint8_t* entrada, int n) {
    // Cabecera zlib: CMF=0x78, FLG=0x01 (válido: 0x7801 % 31 == 0).
    salida[0] = 0x78;
    salida[1] = 0x01;

    EscritorBits b(salida, 2);
    b.put(1, 1);   // BFINAL = 1 (único bloque)
    b.put(1, 2);   // BTYPE  = 01 (Huffman fijo)

    // LZ77 con tabla hash de 3 bytes + cadenas (prev).
    const int HBITS = 15, HSIZE = 1 << HBITS, HMASK = HSIZE - 1;
    const int MAX_CADENA = 256, MIN_MATCH = 3, MAX_MATCH = 258, MAX_DIST = 32768;
    std::vector<int> head(HSIZE, -1);
    std::vector<int> prev(n > 0 ? n : 1, -1);
    auto hash3 = [&](int p) -> int {
        return ((entrada[p] << 10) ^ (entrada[p + 1] << 5) ^ entrada[p + 2]) & HMASK;
    };

    int i = 0;
    while (i < n) {
        int mejorLen = 0, mejorDist = 0;
        if (i + MIN_MATCH <= n) {
            int h = hash3(i);
            int cand = head[h];
            int limite = (n - i < MAX_MATCH) ? (n - i) : MAX_MATCH;
            int pasos = MAX_CADENA;
            while (cand >= 0 && pasos-- > 0) {
                int dist = i - cand;
                if (dist > MAX_DIST) break;
                // Comparar bytes mientras coincidan.
                int len = 0;
                while (len < limite && entrada[cand + len] == entrada[i + len]) len++;
                if (len > mejorLen) { mejorLen = len; mejorDist = dist; if (len >= limite) break; }
                cand = prev[cand];
            }
        }

        if (mejorLen >= MIN_MATCH) {
            int li = indiceLongitud(mejorLen);
            emitirSimbolo(b, 257 + li);
            if (LEXTRA[li]) b.put(mejorLen - LBASE[li], LEXTRA[li]);
            int di = indiceDistancia(mejorDist);
            b.put(invertir(di, 5), 5);                 // código de distancia (5 bits, fijo)
            if (DEXTRA[di]) b.put(mejorDist - DBASE[di], DEXTRA[di]);
            // Insertar en la tabla hash todas las posiciones cubiertas por el match.
            int fin = i + mejorLen;
            while (i < fin) {
                if (i + MIN_MATCH <= n) { int h = hash3(i); prev[i] = head[h]; head[h] = i; }
                i++;
            }
        } else {
            emitirSimbolo(b, entrada[i]);              // literal
            if (i + MIN_MATCH <= n) { int h = hash3(i); prev[i] = head[h]; head[h] = i; }
            i++;
        }
    }

    emitirSimbolo(b, 256);   // fin de bloque
    b.flush();

    // Adler-32 del original, big-endian.
    uint32_t ad = adler32(entrada, n);
    salida[b.o++] = (uint8_t)(ad >> 24);
    salida[b.o++] = (uint8_t)(ad >> 16);
    salida[b.o++] = (uint8_t)(ad >> 8);
    salida[b.o++] = (uint8_t)(ad & 0xff);
    return b.o;
}

} // namespace cifrado
} // namespace prison
