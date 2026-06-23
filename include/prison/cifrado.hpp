// ============================================================================
//  cifrado.hpp  —  Cifrado XOR del protocolo SNS  +  compresión zlib "stored"
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  1) CIFRADO SNS (XOR encadenado):
//     Una vez establecida la conexión, los datos de aplicación viajan
//     "ofuscados" con una clave XOR de 4 bytes (K). No es criptografía fuerte,
//     es una simple mezcla reversible que el cliente "Carcelclient.exe" usa.
//
//        descifrar()  ->  convierte bytes cifrados (que llegan) en datos legibles
//        cifrar()     ->  convierte nuestros datos en bytes cifrados (para enviar)
//
//     Cada byte se mezcla con: un byte de la clave, su posición (i) y el byte
//     anterior (encadenado). La semilla inicial del encadenado es 0x3b.
//
//  2) COMPRESIÓN ZLIB "STORED":
//     Algunas listas (servidores, mapas, clases) viajan comprimidas con zlib.
//     El cliente las descomprime con la librería zlib real. Para no depender de
//     zlib, generamos un flujo zlib VÁLIDO pero SIN comprimir de verdad (bloques
//     "stored" = almacenados tal cual). El cliente lo acepta igual.
//
//        comprimirZlibStored()  ->  envuelve datos crudos en un flujo zlib válido
//        adler32()              ->  checksum que zlib pone al final del flujo
// ============================================================================
#pragma once

#include <cstdint>

namespace prison {
namespace cifrado {

// ---- CIFRADO XOR del protocolo SNS (fase de datos) ----

// Descifra el payload EN EL SITIO (modifica el propio buffer).
//   payload = puntero al inicio de los datos cifrados (wire + 0x16)
//   n       = longitud de los datos
//   clave   = clave XOR negociada (K) de la conexión
void descifrar(uint8_t* payload, int n, uint32_t clave);

// Cifra el payload EN EL SITIO (para enviar datos servidor -> cliente).
void cifrar(uint8_t* payload, int n, uint32_t clave);

// ---- COMPRESIÓN ZLIB (bloques "stored", sin comprimir realmente) ----

// Checksum Adler-32 (lo exige el formato zlib al final del flujo).
uint32_t adler32(const uint8_t* datos, int n);

// Envuelve "entrada" (n bytes) en un flujo zlib válido escrito en "salida".
// Devuelve la longitud total del flujo zlib generado.
int comprimirZlibStored(uint8_t* salida, const uint8_t* entrada, int n);

} // namespace cifrado
} // namespace prison
