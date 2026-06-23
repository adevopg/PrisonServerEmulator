// ============================================================================
//  base_datos.cpp  —  Implementación del acceso a MySQL (ver base_datos.hpp)
// ============================================================================
#include "prison/base_datos.hpp"
#include "prison/registro.hpp"

#include <mysql.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <map>

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

    // Pedimos las fechas como epoch (UNIX_TIMESTAMP) para compararlas fácil.
    // Columnas: 0=id 1=password_hash 2=gm_level 3=banned 4=banned_until(epoch)
    //           5=subscription_until(epoch) 6=created_at(epoch)
    char consulta[420];
    snprintf(consulta, sizeof consulta,
             "SELECT id, password_hash, gm_level, banned, "
             "UNIX_TIMESTAMP(banned_until), UNIX_TIMESTAMP(subscription_until), "
             "UNIX_TIMESTAMP(created_at) "
             "FROM accounts WHERE username='%s' LIMIT 1",
             usuarioEscapado);

    if (mysql_query(mysql_, consulta)) return resultado;

    MYSQL_RES* res = mysql_store_result(mysql_);
    if (res) {
        MYSQL_ROW fila = mysql_fetch_row(res);
        if (fila) {
            resultado.encontrada      = true;
            resultado.id              = static_cast<uint32_t>(strtoul(fila[0], nullptr, 10));
            resultado.hashContrasena  = fila[1] ? fila[1] : "";
            resultado.nivelGm         = fila[2] ? static_cast<uint32_t>(strtoul(fila[2], nullptr, 10)) : 0;
            resultado.baneada         = fila[3] && strtoul(fila[3], nullptr, 10) != 0;
            resultado.baneadaHasta    = fila[4] ? static_cast<uint32_t>(strtoul(fila[4], nullptr, 10)) : 0;
            resultado.suscripcionHasta = fila[5] ? static_cast<uint32_t>(strtoul(fila[5], nullptr, 10)) : 0;
            resultado.creadaEpoch     = fila[6] ? static_cast<uint32_t>(strtoul(fila[6], nullptr, 10)) : 0;
        }
        mysql_free_result(res);
    }
    return resultado;
}

std::vector<ServidorJuego> BaseDatos::listarServidores() {
    std::vector<ServidorJuego> servidores;
    if (!mysql_) return servidores;

    // Todos los campos que el cliente necesita por prisión.
    const char* consulta =
        "SELECT id, name, name2, flag, extra, modules FROM game_servers "
        "WHERE online=1 ORDER BY sort_order";

    if (mysql_query(mysql_, consulta) != 0) return servidores;

    MYSQL_RES* res = mysql_store_result(mysql_);
    if (res) {
        MYSQL_ROW fila;
        while ((fila = mysql_fetch_row(res)) != nullptr) {
            ServidorJuego s;
            s.id        = static_cast<uint32_t>(strtoul(fila[0], nullptr, 10));
            s.nombre    = fila[1] ? fila[1] : "";
            s.nombre2   = fila[2] ? fila[2] : "";
            s.flag      = fila[3] ? static_cast<uint8_t>(strtoul(fila[3], nullptr, 10)) : 2;
            s.extra     = fila[4] ? static_cast<uint32_t>(strtoul(fila[4], nullptr, 10)) : 0;
            s.modulos   = fila[5] ? static_cast<uint8_t>(strtoul(fila[5], nullptr, 10)) : 4;
            servidores.push_back(std::move(s));
        }
        mysql_free_result(res);
    }
    return servidores;
}

// Ejecuta un "SELECT COUNT(*) ..." y devuelve el número.
static int contarFilas(MYSQL* mysql, const char* consulta) {
    if (!mysql || mysql_query(mysql, consulta)) return 0;
    int n = 0;
    MYSQL_RES* res = mysql_store_result(mysql);
    if (res) {
        MYSQL_ROW fila = mysql_fetch_row(res);
        if (fila && fila[0]) n = atoi(fila[0]);
        mysql_free_result(res);
    }
    return n;
}

InfoClases BaseDatos::cargarClases() {
    InfoClases info;
    if (!mysql_) return info;

    auto query = [&](const char* q) -> MYSQL_RES* {
        return mysql_query(mysql_, q) ? nullptr : mysql_store_result(mysql_);
    };

    // 1) Atributos (orden) -> nombres + mapa id->indice.
    std::map<uint32_t, int> idxAttr;
    if (MYSQL_RES* r = query("SELECT id, nombre FROM atributos ORDER BY sort_order, id")) {
        MYSQL_ROW f;
        while ((f = mysql_fetch_row(r))) {
            idxAttr[(uint32_t)strtoul(f[0], nullptr, 10)] = (int)info.nombresAtributos.size();
            info.nombresAtributos.push_back(f[1] ? f[1] : "");
        }
        mysql_free_result(r);
    }
    // 2) Habilidades (orden) -> nombres + mapa id->indice.
    std::map<uint32_t, int> idxHab;
    if (MYSQL_RES* r = query("SELECT id, nombre FROM habilidades ORDER BY sort_order, id")) {
        MYSQL_ROW f;
        while ((f = mysql_fetch_row(r))) {
            idxHab[(uint32_t)strtoul(f[0], nullptr, 10)] = (int)info.nombresHabilidades.size();
            info.nombresHabilidades.push_back(f[1] ? f[1] : "");
        }
        mysql_free_result(r);
    }
    int N1 = (int)info.nombresAtributos.size();
    int N2 = (int)info.nombresHabilidades.size();

    // 3) Valores de atributo por delito: mapa (delito,attrIdx) -> (a0,a1).
    std::map<std::pair<uint32_t,int>, std::array<uint8_t,2>> valAttr;
    if (MYSQL_RES* r = query("SELECT delito_id, atributo_id, a0, a1 FROM delito_atributo")) {
        MYSQL_ROW f;
        while ((f = mysql_fetch_row(r))) {
            auto it = idxAttr.find((uint32_t)strtoul(f[1], nullptr, 10));
            if (it == idxAttr.end()) continue;
            valAttr[{(uint32_t)strtoul(f[0],nullptr,10), it->second}] =
                {(uint8_t)strtoul(f[2],nullptr,10), (uint8_t)strtoul(f[3],nullptr,10)};
        }
        mysql_free_result(r);
    }
    // 4) Habilidades por delito: columnas claras (maximo, inicial, nivel).
    //    Se traducen a los 4 bytes que espera el cliente:
    //      h0 = maximo (el cliente lo muestra x1.5; 0xff = la clase no la tiene)
    //      h1 = inicial (puntos al nivel 1)
    //      h2 = nivel requerido para entrenar (0 = desde el nivel 1)
    //      h3 = 0
    std::map<std::pair<uint32_t,int>, std::array<uint8_t,4>> valHab;
    if (MYSQL_RES* r = query("SELECT delito_id, habilidad_id, maximo, inicial, nivel FROM delito_habilidad")) {
        MYSQL_ROW f;
        while ((f = mysql_fetch_row(r))) {
            auto it = idxHab.find((uint32_t)strtoul(f[1], nullptr, 10));
            if (it == idxHab.end()) continue;
            valHab[{(uint32_t)strtoul(f[0],nullptr,10), it->second}] =
                {(uint8_t)strtoul(f[2],nullptr,10),   // maximo  -> h0
                 (uint8_t)strtoul(f[3],nullptr,10),   // inicial -> h1
                 (uint8_t)strtoul(f[4],nullptr,10),   // nivel   -> h2
                 0};
        }
        mysql_free_result(r);
    }
    // 5) Delitos (en orden de id) + rellenar sus atributos y habilidades.
    if (MYSQL_RES* r = query("SELECT id, nombre_m, nombre_f FROM delitos ORDER BY id")) {
        MYSQL_ROW f;
        while ((f = mysql_fetch_row(r))) {
            uint32_t did = (uint32_t)strtoul(f[0], nullptr, 10);
            DelitoClase d;
            d.nombreM = f[1] ? f[1] : "";
            d.nombreF = f[2] ? f[2] : "";
            for (int a = 0; a < N1; a++) {
                auto it = valAttr.find({did, a});
                d.atributos.push_back(it != valAttr.end() ? it->second
                                                          : std::array<uint8_t,2>{10, 0});
            }
            for (int h = 0; h < N2; h++) {
                auto it = valHab.find({did, h});
                // Sin fila => el delito NO tiene esa habilidad: 0xff = oculta.
                d.habilidades.push_back(it != valHab.end() ? it->second
                                                           : std::array<uint8_t,4>{0xff, 0, 0, 0});
            }
            info.delitos.push_back(std::move(d));
        }
        mysql_free_result(r);
    }
    return info;
}

int BaseDatos::contarPersonajes(uint32_t idCuenta) {
    char consulta[160];
    snprintf(consulta, sizeof consulta,
             "SELECT COUNT(*) FROM characters WHERE account_id=%u AND deleted=0", idCuenta);
    return contarFilas(mysql_, consulta);
}

int BaseDatos::contarReclusos(uint32_t idServidor) {
    char consulta[160];
    snprintf(consulta, sizeof consulta,
             "SELECT COUNT(*) FROM characters WHERE server_id=%u AND deleted=0", idServidor);
    return contarFilas(mysql_, consulta);
}

bool BaseDatos::existeNick(const std::string& nick) {
    if (!mysql_) return false;
    char esc[128];
    mysql_real_escape_string(mysql_, esc, nick.c_str(), static_cast<unsigned long>(nick.size()));
    char consulta[256];
    snprintf(consulta, sizeof consulta,
             "SELECT COUNT(*) FROM characters WHERE nick='%s'", esc);
    return contarFilas(mysql_, consulta) > 0;
}

std::vector<Personaje> BaseDatos::cargarPersonajes(uint32_t idCuenta) {
    std::vector<Personaje> personajes;
    if (!mysql_) return personajes;
    char consulta[220];
    snprintf(consulta, sizeof consulta,
             "SELECT slot, nick, sex, class, level, server_id, module, appearance FROM characters "
             "WHERE account_id=%u AND deleted=0 ORDER BY slot", idCuenta);
    if (mysql_query(mysql_, consulta)) return personajes;
    MYSQL_RES* res = mysql_store_result(mysql_);
    if (res) {
        MYSQL_ROW fila;
        while ((fila = mysql_fetch_row(res)) != nullptr) {
            Personaje p;
            p.slot  = fila[0] ? atoi(fila[0]) : 0;
            p.nick  = fila[1] ? fila[1] : "";
            p.sexo  = fila[2] ? static_cast<uint8_t>(atoi(fila[2])) : 0;
            p.clase = fila[3] ? static_cast<uint8_t>(atoi(fila[3])) : 0;
            p.nivel    = fila[4] ? static_cast<uint32_t>(strtoul(fila[4], nullptr, 10)) : 1;
            p.servidor = fila[5] ? static_cast<uint32_t>(strtoul(fila[5], nullptr, 10)) : 1;
            p.modulo   = fila[6] ? static_cast<uint8_t>(strtoul(fila[6], nullptr, 10)) : 1;
            // appearance es binario (puede tener nulls): usar la longitud real.
            unsigned long* lens = mysql_fetch_lengths(res);
            if (fila[7] && lens && lens[7] > 0)
                p.datos.assign(fila[7], fila[7] + lens[7]);
            personajes.push_back(std::move(p));
        }
        mysql_free_result(res);
    }
    return personajes;
}

bool BaseDatos::crearPersonaje(uint32_t idCuenta, uint32_t idServidor, uint8_t modulo,
                               int slot, const std::string& nick,
                               const uint8_t* datos, int longitudDatos) {
    if (!mysql_) return false;

    // Escapar el nick (texto) y el bloque de datos (binario) para el SQL.
    char nickEsc[128];
    mysql_real_escape_string(mysql_, nickEsc, nick.c_str(),
                             static_cast<unsigned long>(nick.size()));

    std::string blobEsc;
    if (datos && longitudDatos > 0) {
        std::vector<char> tmp(static_cast<size_t>(longitudDatos) * 2 + 1);
        unsigned long m = mysql_real_escape_string(
            mysql_, tmp.data(), reinterpret_cast<const char*>(datos),
            static_cast<unsigned long>(longitudDatos));
        blobEsc.assign(tmp.data(), m);
    }

    std::string q = "INSERT INTO characters (account_id, server_id, module, slot, nick, appearance) VALUES (";
    q += std::to_string(idCuenta) + ", " + std::to_string(idServidor) + ", " +
         std::to_string((unsigned)modulo) + ", " + std::to_string(slot) + ", '" + nickEsc + "', ";
    q += blobEsc.empty() ? "NULL)" : ("'" + blobEsc + "')");

    return mysql_query(mysql_, q.c_str()) == 0;
}

} // namespace prison
