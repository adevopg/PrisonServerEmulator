// ============================================================================
//  registro.hpp  —  Sistema de mensajes/logs del servidor
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  Mientras el servidor funciona necesitamos VER qué está pasando: quién se
//  conecta, qué paquetes llegan, qué respondemos. Este módulo escribe esos
//  mensajes a la vez en:
//
//      - la consola (la ventana negra donde se ejecuta el servidor)
//      - un archivo de texto (login_server.log) para revisarlo después
//
//  Cada mensaje lleva delante la hora (HH:MM:SS.mmm).
//
//  Funciones:
//      registro::abrir("login_server.log")   -> abre el archivo de log
//      registro::log("texto %d", numero)     -> escribe un mensaje (estilo printf)
//      registro::volcadoHex("etiqueta", datos, n)  -> muestra bytes en hexadecimal
//      registro::cerrar()                    -> cierra el archivo
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace prison {
namespace registro {

// Abre el archivo de log (modo "añadir", no borra lo anterior).
void abrir(const char* ruta);

// Cierra el archivo de log.
void cerrar();

// Escribe un mensaje con formato printf (ej: log("usuario %s", nombre)).
void log(const char* formato, ...);

// Muestra un bloque de bytes en hexadecimal (útil para depurar paquetes).
//   etiqueta = texto descriptivo que aparece encima del volcado
//   datos    = puntero a los bytes
//   longitud = cuántos bytes mostrar
void volcadoHex(const char* etiqueta, const uint8_t* datos, int longitud);

} // namespace registro
} // namespace prison
