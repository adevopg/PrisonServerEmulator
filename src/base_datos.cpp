// ============================================================================
//  base_datos.cpp  —  Implementación del acceso a MySQL (ver base_datos.hpp)
// ============================================================================
#include "prison/base_datos.hpp"
#include "prison/registro.hpp"

#include <mysql.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace prison {

// ---- Datos de conexión a MySQL ----
// (Si cambias usuario/contraseña/base de datos, hazlo aquí.)
static const char* BD_HOST     = "127.0.0.1";
static const char* BD_USUARIO  = "Inna";
static const char* BD_PASSWORD = "Ladyamy89";
static const char* BD_NOMBRE   = "prison";
static const unsigned BD_PUERTO = 3306;

BaseDatos::~BaseDatos() {
    if (mysql_) {
        mysql_close(mysql_);
        mysql_ = nullptr;
    }
}

bool BaseDatos::conectar() {
    mysql_ = mysql_init(nullptr);
    if (!mysql_) return false;

    if (!mysql_real_connect(mysql_, BD_HOST, BD_USUARIO, BD_PASSWORD,
                            BD_NOMBRE, BD_PUERTO, nullptr, 0)) {
        // Conexión fallida: dejamos el puntero para poder leer el error,
        // pero estaConectada() devolverá false porque... ojo: aquí mysql_ no es
        // null. Lo cerramos y anulamos para que estaConectada() sea coherente.
        mysql_close(mysql_);
        mysql_ = nullptr;
        return false;
    }
    return true;
}

const char* BaseDatos::ultimoError() const {
    return mysql_ ? mysql_error(mysql_) : "MySQL no inicializado";
}

Cuenta BaseDatos::buscarCuenta(const std::string& usuario) {
    Cuenta resultado;
    if (!mysql_) return resultado;

    // Escapamos el nombre de usuario para evitar inyección SQL.
    char usuarioEscapado[128];
    mysql_real_escape_string(mysql_, usuarioEscapado, usuario.c_str(),
                             static_cast<unsigned long>(usuario.size()));

    char consulta[256];
    snprintf(consulta, sizeof consulta,
             "SELECT id, password, gm_level, banned FROM accounts "
             "WHERE username='%s' LIMIT 1",
             usuarioEscapado);

    if (mysql_query(mysql_, consulta)) return resultado;

    MYSQL_RES* res = mysql_store_result(mysql_);
    if (res) {
        MYSQL_ROW fila = mysql_fetch_row(res);
        if (fila) {
            resultado.encontrada = true;
            resultado.id      = static_cast<uint32_t>(strtoul(fila[0], nullptr, 10));
            resultado.nivelGm = fila[2] ? static_cast<uint32_t>(strtoul(fila[2], nullptr, 10)) : 0;
            resultado.baneada = fila[3] && strtoul(fila[3], nullptr, 10) != 0;
        }
        mysql_free_result(res);
    }
    return resultado;
}

std::vector<ServidorJuego> BaseDatos::listarServidores(int limite) {
    std::vector<ServidorJuego> servidores;
    if (!mysql_) return servidores;

    char consulta[256];
    snprintf(consulta, sizeof consulta,
             "SELECT id, name, population FROM game_servers "
             "WHERE online=1 ORDER BY sort_order LIMIT %d",
             limite);

    if (mysql_query(mysql_, consulta) != 0) return servidores;

    MYSQL_RES* res = mysql_store_result(mysql_);
    if (res) {
        MYSQL_ROW fila;
        while ((fila = mysql_fetch_row(res)) != nullptr) {
            ServidorJuego s;
            s.id        = static_cast<uint32_t>(strtoul(fila[0], nullptr, 10));
            s.nombre    = fila[1] ? fila[1] : "";
            s.poblacion = fila[2] ? static_cast<uint32_t>(strtoul(fila[2], nullptr, 10)) : 0;
            servidores.push_back(std::move(s));
        }
        mysql_free_result(res);
    }
    return servidores;
}

} // namespace prison
