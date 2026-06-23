// ============================================================================
//  protocolo_sns.cpp  —  Implementación de helpers del protocolo SNS
//                        (ver protocolo_sns.hpp)
// ============================================================================
#include "prison/protocolo_sns.hpp"
#include "prison/utilidades.hpp"
#include <cstring>

namespace prison {
namespace protocolo {

int componerMensajeApp(uint8_t* salida, uint32_t idConexion,
                       const uint8_t* datosApp, int n) {
    int longRegistro = 8 + n;                  // = [idConexion][1][datosApp]

    // Prefijo del payload (el cliente lo descarta tras leerlo).
    escribir32(salida + 0, idConexion);
    escribir32(salida + 4, 1);

    // M[0] = longitud del registro.
    escribir32(salida + 8, static_cast<uint32_t>(longRegistro));

    // Cabecera del registro.
    escribir32(salida + 12, idConexion);
    escribir32(salida + 16, 1);

    // Cuerpo del registro = los datos de aplicación.
    if (n) memcpy(salida + 20, datosApp, n);

    // Terminador: un registro de longitud 0.
    escribir32(salida + 20 + n, 0);

    return 24 + n;
}

} // namespace protocolo
} // namespace prison
