// ============================================================================
//  registro.cpp  —  Implementación del sistema de logs (ver registro.hpp)
// ============================================================================
#include "prison/registro.hpp"
#include "prison/monitor.hpp"

#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <string>

namespace prison {
namespace registro {

// Archivo de log abierto. Si es nullptr, solo se escribe en consola.
static FILE* g_archivoLog = nullptr;

// Escribe la hora actual "HH:MM:SS.mmm" en el buffer dado.
static void horaActual(char* buffer, size_t tam) {
    SYSTEMTIME t;
    GetLocalTime(&t);
    snprintf(buffer, tam, "%02d:%02d:%02d.%03d",
             t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
}

void abrir(const char* ruta) {
    g_archivoLog = fopen(ruta, "a");
}

void cerrar() {
    if (g_archivoLog) {
        fclose(g_archivoLog);
        g_archivoLog = nullptr;
    }
}

void log(const char* formato, ...) {
    char hora[32];
    horaActual(hora, sizeof hora);

    // Construir el mensaje aplicando el formato (estilo printf).
    char mensaje[2048];
    va_list args;
    va_start(args, formato);
    vsnprintf(mensaje, sizeof mensaje, formato, args);
    va_end(args);

    // Línea completa "[hora] mensaje".
    char linea[2100];
    snprintf(linea, sizeof linea, "[%s] %s", hora, mensaje);

    // Enviar a la ventana (consola de la GUI).
    monitor::emitirLog(linea);

    // Escribir en el archivo (si está abierto).
    if (g_archivoLog) {
        fprintf(g_archivoLog, "%s\n", linea);
        fflush(g_archivoLog);
    }
}

void volcadoHex(const char* etiqueta, const uint8_t* datos, int longitud) {
    std::string salida = etiqueta;
    salida += "\n";

    char linea[160];
    for (int i = 0; i < longitud; i += 16) {
        int n = 0;
        // Dirección (offset) al inicio de la línea.
        n += snprintf(linea + n, sizeof linea - n, "    %04x  ", i);

        // 16 bytes en hexadecimal.
        for (int j = 0; j < 16; j++) {
            if (i + j < longitud)
                n += snprintf(linea + n, sizeof linea - n, "%02x ", datos[i + j]);
            else
                n += snprintf(linea + n, sizeof linea - n, "   ");
            if (j == 7) n += snprintf(linea + n, sizeof linea - n, " ");
        }

        // Representación ASCII a la derecha (los bytes "imprimibles").
        n += snprintf(linea + n, sizeof linea - n, " |");
        for (int j = 0; j < 16 && i + j < longitud; j++) {
            uint8_t c = datos[i + j];
            linea[n++] = (c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.';
        }
        linea[n++] = '|';
        linea[n] = 0;

        salida += "    ";
        salida += linea;
        salida += "\n";
    }
    log("%s", salida.c_str());
}

} // namespace registro
} // namespace prison
