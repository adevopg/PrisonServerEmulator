// ============================================================================
//  servidor_login.cpp  —  Implementación del servidor de LOGIN (ver .hpp)
// ============================================================================
//
//  ATENCIÓN: la lógica byte a byte (offsets, opcodes, tamaños de estructuras)
//  está sacada de la ingeniería inversa del cliente "Carcelclient.exe" y es
//  MUY sensible. Los comentarios indican de dónde sale cada cosa (direcciones
//  como 0x40a59e son funciones del cliente). No cambiar sin saber por qué.
// ============================================================================
#include "prison/servidor_login.hpp"
#include "prison/protocolo_sns.hpp"
#include "prison/opcodes.hpp"
#include "prison/configuracion.hpp"
#include "prison/cifrado.hpp"
#include "prison/utilidades.hpp"
#include "prison/registro.hpp"

#include <windows.h>   // Sleep
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <string>

namespace prison {

using boost::asio::ip::udp;
namespace pr = prison::protocolo;

ServidorLogin::ServidorLogin(boost::asio::io_context& io, BaseDatos& bd)
    : ServidorUdp(io, "LOGIN", pr::PUERTO_LOGIN), bd_(bd) {
    contadorMarcaTiempo_ = 0x11223344; // valor inicial original del login
}

void ServidorLogin::procesarPaquete(uint8_t* buf, int n, const udp::endpoint& remoto) {
    std::string ip = remoto.address().to_string();
    uint16_t puertoRemoto = remoto.port();

    if (n < pr::TAM_CABECERA) {
        registro::log("<- %s:%u paquete corto len=%d", ip.c_str(), puertoRemoto, n);
        return;
    }

    // --- Leer la cabecera SNS ---
    uint32_t connLo  = leer32(buf + pr::OFF_CONN_LO);
    uint32_t connHi  = leer32(buf + pr::OFF_CONN_HI);
    uint16_t flags   = leer16(buf + pr::OFF_FLAGS);
    uint8_t  ventana = buf[pr::OFF_VENTANA];
    uint8_t  ack     = buf[pr::OFF_ACK];
    uint32_t campoC  = leer32(buf + pr::OFF_CAMPO_C);
    uint32_t marcaT  = leer32(buf + pr::OFF_MARCA_TIEMPO);
    uint16_t secuencia = leer16(buf + pr::OFF_SECUENCIA);
    uint16_t tipo    = leer16(buf + pr::OFF_TIPO);
    uint16_t cst     = (n >= 0x1a) ? leer16(buf + pr::OFF_CONST) : 0;
    uint32_t nonce   = (n >= 0x1e) ? leer32(buf + pr::OFF_NONCE) : 0;

    bool esHandshake = (connLo == pr::CONN_HANDSHAKE);
    registro::log("<- %s:%u len=%d %s connLo=%08x connHi=%08x flags=%u win=%u ack=%u seq=%u tipo=%u const=%u nonce=%08x",
                  ip.c_str(), puertoRemoto, n, esHandshake ? "HS" : "DATOS",
                  connLo, connHi, flags, ventana, ack, secuencia, tipo, cst, nonce);

    uint64_t clave = claveDeConexion(remoto);

    // Marcar "última actividad" de esta conexión (para la caducidad de "cuenta en uso").
    {
        auto itAct = conexiones_.find(clave);
        if (itAct != conexiones_.end())
            itAct->second.ultimaActividad = static_cast<uint32_t>(time(nullptr));
    }

    // ===================== HANDSHAKE =====================
    if (esHandshake && tipo == pr::TIPO_SYN) {
        // SYN: el nombre de usuario va tras el nonce (wire[0x1e..], terminado en NUL).
        std::string usuario;
        if (n > pr::OFF_DATOS)
            usuario.assign(reinterpret_cast<const char*>(buf + pr::OFF_DATOS),
                           static_cast<size_t>(n - pr::OFF_DATOS));
        size_t z = usuario.find('\0');
        if (z != std::string::npos) usuario.resize(z);
        registro::log("   SYN(tipo3) usuario='%s' nonceCliente=%08x seq=%u",
                      usuario.c_str(), nonce, secuencia);

        // Crear el estado de la conexión.
        Conexion c;
        c.idConexion = siguienteId_++;
        c.clave = 0xA5A5A5A5u ^ static_cast<uint32_t>(clave);
        c.fase = Fase::SynRespondido;
        c.usuario = usuario;
        if (cfg().tieneStartFieldc)
            c.idMensajeTx = static_cast<uint32_t>(cfg().startFieldc - 1);

        // Buscar la cuenta en MySQL (la validación de contraseña/estado se hace
        // luego, en el LOGIN, porque la contraseña llega en ese mensaje).
        Cuenta cuenta = bd_.buscarCuenta(usuario);
        c.cuenta = cuenta;
        c.idCuenta = cuenta.id;
        registro::log("   MySQL: usuario='%s' -> %s idCuenta=%u",
                      usuario.c_str(), cuenta.encontrada ? "ENCONTRADA" : "NO ENCONTRADA", c.idCuenta);
        c.ultimaActividad = static_cast<uint32_t>(time(nullptr));
        conexiones_[clave] = c;

        // Construir el SYN-ACK con el intercambio de clave.
        uint32_t K  = c.clave;
        uint32_t TS = contadorMarcaTiempo_++;
        uint32_t f1 = ((TS ^ K) & pr::MASCARA_CLAVE) ^ K;   // wire[0x10]
        uint32_t f2 = ((TS ^ K) & pr::MASCARA_CLAVE) ^ TS;  // wire[0x0c]

        uint8_t r[34];
        memset(r, 0, sizeof r);
        escribir32(r + pr::OFF_CONN_LO, 0xFFFFFFFFu);
        escribir32(r + pr::OFF_CONN_HI, 0xFFFFFFFFu);
        escribir16(r + pr::OFF_FLAGS, 0);
        r[pr::OFF_VENTANA] = 1;
        r[pr::OFF_ACK] = 0;
        escribir32(r + pr::OFF_CAMPO_C, f2);
        escribir32(r + pr::OFF_MARCA_TIEMPO, f1);
        escribir16(r + pr::OFF_SECUENCIA, secuencia);   // eco de la seq del cliente
        escribir16(r + pr::OFF_TIPO, pr::TIPO_SYN_ACK); // tipo 6
        escribir16(r + pr::OFF_CONST, 4);
        escribir32(r + pr::OFF_NONCE, nonce);           // eco del nonce del cliente
        escribir32(r + pr::OFF_DATOS, c.idConexion);    // id de conexión asignado
        enviar(r, sizeof r, remoto);
        registro::log("   -> tipo6 SYN-ACK idConexion=%08x K=%08x TS=%08x f1=%08x f2=%08x",
                      c.idConexion, K, TS, f1, f2);
        return;
    }

    if (esHandshake && tipo == pr::TIPO_ACK) {
        auto it = conexiones_.find(clave);
        if (it != conexiones_.end()) {
            it->second.fase = Fase::Establecida;
            registro::log("   ACK(tipo7) -> ESTABLECIDA usuario='%s' idConexion=%08x",
                          it->second.usuario.c_str(), it->second.idConexion);
        } else {
            registro::log("   ACK(tipo7) para conexión desconocida");
        }
        return;
    }

    // Tipo 4 = el cliente CIERRA la conexión (FIN de transporte). El protocolo
    // SNS responde con tipo 5 (FIN-ACK): así el cliente da el cierre por
    // confirmado y DEJA de reintentar (antes no le contestábamos y reenviaba
    // ~10 veces). Respondemos copiando su paquete y cambiando el tipo a 5.
    if (esHandshake && tipo == 4) {
        uint8_t r[64];
        int len = (n < static_cast<int>(sizeof r)) ? n : static_cast<int>(sizeof r);
        memcpy(r, buf, len);
        escribir16(r + pr::OFF_TIPO, 5);   // tipo 5 = confirmación de cierre (FIN-ACK)
        enviar(r, len, remoto);

        auto it = conexiones_.find(clave);
        if (it != conexiones_.end()) {
            registro::log("   handshake tipo4 (FIN) usuario='%s' -> tipo5 (FIN-ACK), cierro conexión",
                          it->second.usuario.c_str());
            conexiones_.erase(it);
        }
        return;
    }

    if (esHandshake) {
        registro::log("   handshake tipo=%u (aún no manejado)", tipo);
        return;
    }

    // ===================== FASE DE DATOS =====================
    procesarDatos(buf, n, remoto, flags, secuencia);
}

void ServidorLogin::procesarDatos(uint8_t* buf, int n, const udp::endpoint& remoto,
                                  uint16_t flags, uint16_t secuencia) {
    uint64_t clave = claveDeConexion(remoto);
    auto it = conexiones_.find(clave);

    uint32_t K = (it != conexiones_.end()) ? it->second.clave : 0;
    uint32_t miConn = (it != conexiones_.end()) ? it->second.idConexion
                                                : leer32(buf + pr::OFF_CONN_LO);

    // --- Si el cliente pide ACK (flag bit0), confirmamos ---
    if (flags & pr::FLAG_PIDE_ACK) {
        uint8_t r[pr::TAM_CABECERA];
        memset(r, 0, sizeof r);
        escribir32(r + pr::OFF_CONN_LO, 0x00000001u);
        escribir32(r + pr::OFF_CONN_HI, miConn);
        escribir16(r + pr::OFF_FLAGS, pr::FLAG_ES_ACK);  // ACK puro
        r[pr::OFF_VENTANA] = 1;
        r[pr::OFF_ACK] = 0;
        memcpy(r + pr::OFF_CAMPO_C,      buf + pr::OFF_CAMPO_C, 4);      // eco del id de mensaje
        memcpy(r + pr::OFF_MARCA_TIEMPO, buf + pr::OFF_MARCA_TIEMPO, 4); // eco del timestamp
        memcpy(r + pr::OFF_SECUENCIA,    buf + pr::OFF_SECUENCIA, 2);    // eco de la seq
        enviar(r, sizeof r, remoto);
        registro::log("   -> ACK idMensaje=%08x seq=%u",
                      leer32(buf + pr::OFF_CAMPO_C), secuencia);
    }

    int plen = n - pr::OFF_PAYLOAD;
    uint8_t* pay = buf + pr::OFF_PAYLOAD;

    // Sin clave o sin datos no hay nada que procesar (p.ej. ACK puro del cliente).
    if (!(K && plen > 0)) return;
    cifrado::descifrar(pay, plen, K);

    // Paquete demasiado corto para llevar opcode (ACK/control): se ignora en silencio.
    if (!(plen >= pr::TAM_CABECERA && it != conexiones_.end())) return;

    Conexion& con = it->second;
    uint16_t opcode = leer16(pay + 0x14);

    // Etiqueta legible de cada opcode que el cliente nos envía, y si lo conocemos.
    const char* etiqueta = "";
    bool conocido = true;
    switch (opcode) {
        case op::CONECTAR_CONFIRMA: etiqueta = " (confirmación de conexión)"; break;
        case op::LOGIN:             etiqueta = " (LOGIN)"; break;
        case op::CREAR_PERSONAJE:   etiqueta = " (crear personaje)"; break;
        case op::SELECCIONAR:       etiqueta = " (auto-seleccionar personaje)"; break;
        case op::LATIDO:            etiqueta = " (latido)"; break;
        case op::JUGAR:             etiqueta = " (JUGAR)"; break;
        default:                    etiqueta = " (DESCONOCIDO)"; conocido = false; break;
    }
    registro::log("   opcode app = 0x%04x%s", opcode, etiqueta);

    // Solo volcamos el hexadecimal de los paquetes que AÚN NO conocemos, para
    // poder estudiarlos. Los conocidos no ensucian el log.
    if (!conocido)
        registro::volcadoHex("   datos del opcode desconocido:", pay, plen);

    // -------------------- LOGIN (0x1388) --------------------
    // Respondemos con la estructura de cuenta (opcode 0x1389) fragmentada.
    // (El cliente hace `dec` en su dispatch, por eso el handler 0x40a59e es 0x1389.)
    if (opcode == op::LOGIN && !con.enviadoLogin) {
        con.enviadoLogin = true;

        // --- Extraer el hash de la contraseña que envía el cliente ---
        // El mensaje LOGIN trae tras el opcode: [u16 ?][u16 longitud][hash...].
        //   pay+0x16 = campo previo, pay+0x18 = longitud, pay+0x1a = hash.
        std::string hashRecibido;
        if (plen >= 0x1a) {
            int longHash = leer16(pay + 0x18);
            if (longHash > 0 && 0x1a + longHash <= plen) {
                static const char* HEX = "0123456789abcdef";
                for (int i = 0; i < longHash; i++) {
                    uint8_t b = pay[0x1a + i];
                    hashRecibido += HEX[b >> 4];
                    hashRecibido += HEX[b & 0xf];
                }
            }
        }
        registro::log("   LOGIN hash recibido=%s", hashRecibido.empty() ? "(ninguno)" : hashRecibido.c_str());

        // --- Comprobar el estado de la cuenta (contraseña, ban, tiempo, etc.) ---
        EstadoCuenta estado = evaluarEstado(con, hashRecibido, clave);
        if (estado != EstadoCuenta::Ok) {
            registro::log("   *** LOGIN RECHAZADO '%s' -> %s (codigo %u) ***",
                          con.usuario.c_str(), nombreEstado(estado), estadoARechazo(estado));
            enviarRechazo(con, remoto, estado);
            return;
        }

        // La cuenta tiene 3 ranuras de personaje (0x9cd = 7 + 3*0x342). Cargamos
        // los personajes REALES de MySQL. Si la cuenta tiene 0, el cliente muestra
        // la pantalla de CREAR personaje (no la de selección).
        std::vector<Personaje> personajes = bd_.cargarPersonajes(con.cuenta.id);
        if (personajes.size() > 3) personajes.resize(3);

        static uint8_t app[2 + 0x9cd];
        memset(app, 0, sizeof app);
        escribir16(app, op::CUENTA);                            // handler de cuenta 0x40a59e
        escribir32(app + 2, con.idCuenta ? con.idCuenta : 1);   // idCuenta en struct[0]
        app[2 + 4] = static_cast<uint8_t>(personajes.size());   // struct+4 = nº de personajes

        // Rellenar cada ranura con su personaje (offsets del render 0x5482ff).
        for (const auto& p : personajes) {
            int s = p.slot; if (s < 0 || s > 2) s = 0;
            uint8_t* ch = app + 2 + 7 + s * 0x342;     // base de la ranura s
            ch[0x00] = 1;                              // +0 existe
            size_t nl = p.nick.size() > 0x1f ? 0x1f : p.nick.size();
            memcpy(ch + 2, p.nick.c_str(), nl);        // +2 nombre
            ch[0x29] = 0;                              // +0x29 flag selección de clase
            ch[0x40] = p.clase;                        // +0x40 índice de clase
            escribir32(ch + 0x34, 1000);              // +0x34 pos X (evita div/0 en el render)
            escribir32(ch + 0x38, 1000);              // +0x38 pos Y
            escribir32(ch + 0x51, 0xFFFFFFFFu);       // +0x51 suprime el auto-enter 0x139f
            escribir32(ch + 0x65, 1);                 // +0x65 id de prisión
            ch[0x69] = static_cast<uint8_t>(p.nivel); // +0x69 nivel (se muestra +1)
            ch[0x6a] = 0;                             // +0x6a estado
        }

        registro::log("   *** LOGIN '%s' OK -> %zu personaje(s) (cuenta 0x1389) ***",
                      con.usuario.c_str(), personajes.size());
        enviarFragmentado(con, remoto, app, 2 + 0x9cd);
    }
    // -------------------- CREAR PERSONAJE (0x1394) --------------------
    // El cliente envía, tras el opcode (pay+0x16): nick (asciiz) + atributos +
    // aspecto. Guardamos el personaje en MySQL y respondemos CHARCREATED (0x1395).
    else if (opcode == op::CREAR_PERSONAJE) {
        const uint8_t* datosCrear = pay + 0x16;            // datos de creación
        int longCrear = plen - 0x16; if (longCrear < 0) longCrear = 0;

        char nick[32] = {0};
        for (int i = 0; i < static_cast<int>(sizeof nick) - 1 && i < longCrear && datosCrear[i]; i++)
            nick[i] = datosCrear[i];
        if (!nick[0]) strcpy(nick, "Recluso");

        // Volcamos el paquete completo para poder mapear cada campo (nick, sexo,
        // clase, atributos, aspecto) a su columna. (Quitar cuando esté mapeado.)
        registro::log("   *** CREAR PERSONAJE nick='%s' (datos=%d bytes) ***", nick, longCrear);
        registro::volcadoHex("   0x1394 CREATE payload:", datosCrear, longCrear);

        // Guardar en la base de datos (de momento: nick + bloque crudo completo).
        int slot = 0;
        if (con.cuenta.id) {
            slot = bd_.contarPersonajes(con.cuenta.id);
            bool ok = bd_.crearPersonaje(con.cuenta.id, slot, nick,
                                         datosCrear, longCrear > 1024 ? 1024 : longCrear);
            registro::log("   -> guardar personaje en BD: %s (cuenta=%u slot=%d)",
                          ok ? "OK" : "FALLÓ", con.cuenta.id, slot);
        } else {
            registro::log("   (sin idCuenta válido: no se guarda en BD)");
        }

        // Responder CHARCREATED (0x1395) para que el cliente lo coloque en la ranura.
        static uint8_t cca[2 + 1 + 0x342];
        memset(cca, 0, sizeof cca);
        escribir16(cca, op::CHARCREATED);
        cca[2] = static_cast<uint8_t>(slot);      // índice de personaje (ranura)
        uint8_t* nch = cca + 3;                   // estructura del personaje (0x342)
        nch[0] = 1;                               // +0 existe
        memcpy(nch + 2, nick, strlen(nick));      // +2 nombre
        nch[0x29] = 0; nch[0x40] = 0;             // +0x29 flag clase, +0x40 índice clase
        escribir32(nch + 0x34, 1000);             // +0x34 pos (evita división por 0 en el render)
        escribir32(nch + 0x38, 1000);             // +0x38 pos
        escribir32(nch + 0x65, 1);                // +0x65 id de prisión 1
        nch[0x69] = 0;                            // +0x69 nivel (se muestra +1)
        nch[0x6a] = 0;                            // +0x6a estado
        enviarFragmentado(con, remoto, cca, 2 + 1 + 0x342);
        registro::log("   -> CHARCREATED (0x1395) ranura=%d", slot);
    }
    // -------------------- LATIDO (0x13a1) -> ACEPTAR + LISTA SERVIDORES --------------------
    else if (opcode == op::LATIDO && con.enviadoLogin && !con.enviadoAceptar) {
        con.enviadoAceptar = true;

        // LOGINACCEPTED (0x13d5 count=0) -> evento 0x482, loginPhase->2
        {
            uint8_t a[6];
            escribir16(a, op::LOGINACCEPTED);
            escribir32(a + 2, 0);
            uint8_t m[64];
            int ml = pr::componerMensajeApp(m, con.idConexion, a, 6);
            enviarFiable(con, remoto, m, ml);
        }

        // Lista de servidores RICA (opcional, RICH_LIST): nombre + reclusos + .skf, comprimida.
        if (cfg().listaRica) {
            uint8_t blob[256]; int bi = 0;
            const char* nm = cfg().nombrePrision.c_str();
            int nl = (int)strlen(nm); memcpy(blob + bi, nm, nl); bi += nl; blob[bi++] = 0;
            uint32_t reclusos = cfg().reclusos;
            escribir32(blob + bi, 1);        bi += 4;   // dword0: id
            escribir32(blob + bi, reclusos); bi += 4;   // dword1: reclusos
            escribir32(blob + bi, 100);      bi += 4;   // dword2: máximo
            escribir32(blob + bi, 0);        bi += 4;   // dword3: flags
            const char* sk = "carcel.skf"; int sl = (int)strlen(sk);
            memcpy(blob + bi, sk, sl); bi += sl; blob[bi++] = 0;

            uint8_t comp[512];
            int cl = cifrado::comprimirZlibStored(comp, blob, bi);
            uint8_t sv[2 + 12 + 512]; int si = 0;
            escribir16(sv, op::LOGINACCEPTED); si = 2;
            escribir32(sv + si, 1); si += 4;            // count
            escribir32(sv + si, (uint32_t)bi); si += 4; // tamaño sin comprimir
            escribir32(sv + si, (uint32_t)cl); si += 4; // tamaño comprimido
            memcpy(sv + si, comp, cl); si += cl;
            enviarFragmentado(con, remoto, sv, si);
            registro::log("   -> 0x13d5 lista RICA (prisión '%s' reclusos=%u)", nm, reclusos);
        }

        // CLASSINFO (opcional, env CLASSINFO): tabla de clases, comprimida. Ver
        // ingeniería inversa del handler 0x4a4620. Necesario para el preview de
        // selección de prisión (evita null-deref en 0x561b10).
        if (cfg().classInfo) {
            const int N0 = 32, N1 = 10, N2 = 0; const char* NM = "Recluso";
            uint8_t blob[8192]; int bl = 0;
            auto putStr = [&](const char* s) {
                int L = (int)strlen(s);
                if (L == 0) { blob[bl++] = 0; }
                else { blob[bl++] = (uint8_t)(L + 1); memcpy(blob + bl, s, L); bl += L; blob[bl++] = 0; }
            };
            blob[bl++] = (uint8_t)N0; blob[bl++] = (uint8_t)N1; blob[bl++] = (uint8_t)N2;
            char an[16];
            for (int i = 0; i < N1; i++) { snprintf(an, sizeof an, "Atrib%d", i); putStr(an); }
            for (int c = 0; c < N0; c++) {
                putStr(NM);                       // -> entry+4 (nombre mostrado)
                putStr(NM);                       // -> entry+0 (nombre alterno)
                putStr("");                       // -> entry+8 (vacío)
                memset(blob + bl, 0, 20); bl += 20;
                for (int a = 0; a < N1; a++) { blob[bl++] = 50; blob[bl++] = 50; } // valores de atributo
            }
            uint8_t comp[8192];
            int cl = cifrado::comprimirZlibStored(comp, blob, bl);
            uint8_t sv[4400]; int si = 0;
            escribir16(sv, op::CLASSINFO); si = 2;
            escribir32(sv + si, 0); si += 4;             // cabecera de 4 bytes (payload[0..3])
            escribir32(sv + si, (uint32_t)bl); si += 4;  // tamaño sin comprimir (payload[4])
            escribir32(sv + si, (uint32_t)cl); si += 4;  // tamaño comprimido   (payload[8])
            memcpy(sv + si, comp, cl); si += cl;
            uint8_t m[4600];
            int ml = pr::componerMensajeApp(m, con.idConexion, sv, si);
            enviarFiable(con, remoto, m, ml);
            registro::log("   -> 0x13c2 CLASSINFO (N0=%d '%s')", N0, NM);
        }

        // --- Lista de prisiones: TODO viene de MySQL (tabla game_servers) ---
        // El cliente admite hasta 255 prisiones; limitamos por seguridad del buffer.
        std::vector<ServidorJuego> servidores = bd_.listarServidores();
        if (servidores.size() > 255) servidores.resize(255);
        registro::log("   prisiones en línea (MySQL) = %zu", servidores.size());

        // SERVERADDED (0x13a9): un nodo por prisión. Por cada una el cliente lee
        //   [id:4][flag:1][extra:4][nombre\0][nombre2\0]  y muestra "nombre nombre2".
        {
            uint8_t sv[4096]; int si = 0;
            escribir16(sv, op::SERVERADDED); si = 2;
            escribir16(sv + si, static_cast<uint16_t>(servidores.size())); si += 2; // count (word)
            for (const auto& s : servidores) {
                escribir32(sv + si, s.id); si += 4;
                sv[si++] = s.flag;
                escribir32(sv + si, s.extra); si += 4;
                int n1 = (int)s.nombre.size();  memcpy(sv + si, s.nombre.c_str(),  n1); si += n1; sv[si++] = 0;
                int n2 = (int)s.nombre2.size(); memcpy(sv + si, s.nombre2.c_str(), n2); si += n2; sv[si++] = 0;
            }
            uint8_t m[4200];
            int ml = pr::componerMensajeApp(m, con.idConexion, sv, si);
            enviarFiable(con, remoto, m, ml);
            registro::log("   -> 0x13a9 SERVERADDED x%zu", servidores.size());
        }

        // AVAILABLESERVERS (0x13ac): por prisión [id:4][nChars:1][texto UTF-16].
        // El cliente usa DOS valores independientes de este texto:
        //   - nChars (nº de caracteres)        -> nº de MÓDULOS de celdas
        //   - SUMA del valor de los caracteres -> nº de RECLUSOS (población)
        // (rutina 0x48a432: add ecx, char). Por eso ponemos nChars = módulos y
        // repartimos la población entre esos caracteres (su suma = reclusos).
        {
            static uint8_t data[256 * (5 + 2 * 255)]; int di = 0;
            for (const auto& s : servidores) {
                uint8_t nMod = s.modulos == 0 ? 1 : s.modulos;   // nChars = nº de módulos
                uint32_t recl = s.poblacion;                     // se reparte en la suma
                escribir32(data + di, s.id); di += 4; data[di++] = nMod;
                for (int k = 0; k < nMod; k++) {
                    // Repartir los reclusos entre los caracteres (cada uno cabe 0..0xffff).
                    uint16_t v = 0;
                    if (recl > 0) { v = recl > 0xffff ? 0xffff : (uint16_t)recl; recl -= v; }
                    data[di++] = (uint8_t)(v & 0xff);
                    data[di++] = (uint8_t)(v >> 8);
                }
            }
            static uint8_t sv[8 + sizeof(data)]; int si = 0;
            escribir16(sv, op::AVAILABLESERVERS); si = 2;
            sv[si++] = static_cast<uint8_t>(servidores.size());   // count (byte)
            escribir32(sv + si, (uint32_t)di); si += 4;
            memcpy(sv + si, data, di); si += di;
            uint8_t smsg[16 + sizeof(sv)];
            int smlen = pr::componerMensajeApp(smsg, con.idConexion, sv, si);
            enviarFiable(con, remoto, smsg, smlen);
            registro::log("   -> 0x13ac AVAILABLESERVERS x%zu", servidores.size());
        }
        registro::log("   -> 0x13d5(aceptar)+0x13a9(prisiones)+0x13ac(reclusos)");
    }
    // -------------------- JUGAR (0x13f1) -> ENTERINGGAMEACCEPTED (0x13f2) --------------------
    // Tras esto el cliente se desconecta del login y se conecta al ServidorMundo.
    else if (opcode == op::JUGAR && !con.enviadoEntrar) {
        con.enviadoEntrar = true;
        uint8_t indicePj = (plen > 0x16) ? pay[0x16] : 0;   // personaje elegido
        uint8_t a[2 + 1 + 4];
        escribir16(a, op::ENTERINGGAMEACCEPTED);   // ENTERINGGAMEACCEPTED
        a[2] = indicePj;         // índice de personaje
        escribir32(a + 3, 0);    // valor (reinterpretado como float)
        uint8_t m[64];
        int ml = pr::componerMensajeApp(m, con.idConexion, a, 2 + 1 + 4);
        enviarFiable(con, remoto, m, ml);
        registro::log("   *** JUGAR (0x13f1 pj=%u) -> 0x13f2 -> el cliente conecta al mundo 25001 ***", indicePj);
    }
    // -------------------- SELECT (0x139f) -> ENTERINGGAMEACCEPTED (opcional, ENTER_GAME) --------------------
    else if (opcode == op::SELECCIONAR && con.enviadoLogin && !con.enviadoEntrar && cfg().enterGame) {
        con.enviadoEntrar = true;
        if (!con.enviadoAceptar) {
            con.enviadoAceptar = true;
            {
                uint8_t a[6]; escribir16(a, 0x13d5); escribir32(a + 2, 0);
                uint8_t m[64]; int ml = pr::componerMensajeApp(m, con.idConexion, a, 6);
                enviarFiable(con, remoto, m, ml);
            }
            {
                const char* nm = "Local"; int nl = (int)strlen(nm);
                uint8_t data[64]; int di = 0;
                escribir32(data + di, 1); di += 4; data[di++] = (uint8_t)nl;
                for (int k = 0; k < nl; k++) { data[di++] = (uint8_t)nm[k]; data[di++] = 0; }
                uint8_t sv[2 + 5 + 64]; int si = 0;
                escribir16(sv, op::AVAILABLESERVERS); si = 2; sv[si++] = 1; escribir32(sv + si, (uint32_t)di); si += 4;
                memcpy(sv + si, data, di); si += di;
                uint8_t smsg[128];
                int smlen = pr::componerMensajeApp(smsg, con.idConexion, sv, si);
                enviarFiable(con, remoto, smsg, smlen);
            }
            registro::log("   -> 0x13d5(aceptar)+0x13ac(servidores) [pre-entrada]");
        }
        uint8_t a[2 + 1 + 4];
        escribir16(a, op::ENTERINGGAMEACCEPTED);   // ENTERINGGAMEACCEPTED
        a[2] = 0;                // índice de personaje 0 (auto)
        escribir32(a + 3, 0);
        uint8_t m[64];
        int ml = pr::componerMensajeApp(m, con.idConexion, a, 2 + 1 + 4);
        enviarFiable(con, remoto, m, ml);
        registro::log("   *** SELECT (0x139f) -> 0x13f2 ENTERINGGAMEACCEPTED (pj 0) ***");
    }
}

// ----------------------------------------------------------------------------
//  Compara el hash de contraseña recibido con el guardado, TOLERANDO la "sal".
//
//  El cliente NO envía siempre el mismo hash: mezcla un valor de sesión que
//  cambia los bytes en las posiciones 0,4,8,12,... (cada 4 bytes). Los otros 15
//  bytes (de 21) son estables para una misma contraseña. Así que comparamos solo
//  los bytes estables (ignoramos los que la sal modifica). Cada byte son 2
//  caracteres hex, por lo que el byte b ocupa los caracteres [2b] y [2b+1].
// ----------------------------------------------------------------------------
static bool contrasenaCoincide(const std::string& recibidoHex,
                               const std::string& guardadoHex) {
    if (recibidoHex.size() != guardadoHex.size() || recibidoHex.empty())
        return false;
    int numBytes = static_cast<int>(recibidoHex.size() / 2);
    for (int b = 0; b < numBytes; b++) {
        if (b % 4 == 0) continue;                 // byte "salado": lo ignoramos
        char r0 = (char)tolower((unsigned char)recibidoHex[2 * b]);
        char r1 = (char)tolower((unsigned char)recibidoHex[2 * b + 1]);
        char g0 = (char)tolower((unsigned char)guardadoHex[2 * b]);
        char g1 = (char)tolower((unsigned char)guardadoHex[2 * b + 1]);
        if (r0 != g0 || r1 != g1) return false;
    }
    return true;
}

// ----------------------------------------------------------------------------
//  ¿Hay otra conexión activa con la misma cuenta? (sesión duplicada)
// ----------------------------------------------------------------------------
bool ServidorLogin::cuentaYaConectada(uint32_t idCuenta, uint64_t claveActual) {
    if (idCuenta == 0) return false; // sin id no comprobamos

    // Como dice el cartel del cliente, "cuenta en uso" solo dura 1 minuto: una
    // conexión cuenta como activa solo si recibió algo en los últimos 60s.
    const uint32_t CADUCIDAD_USO = 60;
    uint32_t ahora = static_cast<uint32_t>(time(nullptr));
    uint32_t ipActual = static_cast<uint32_t>(claveActual >> 16);  // la clave es (ip<<16)|puerto

    for (auto& par : conexiones_) {
        if (par.first == claveActual) continue;                 // la conexión actual
        const Conexion& otra = par.second;
        if (otra.idCuenta != idCuenta || !otra.enviadoLogin) continue;
        if (ahora - otra.ultimaActividad >= CADUCIDAD_USO) continue; // expiró (1 min)
        if (static_cast<uint32_t>(par.first >> 16) == ipActual) continue; // mismo equipo reconectando
        return true; // otra sesión activa, en otro equipo, con esta cuenta
    }
    return false;
}

// ----------------------------------------------------------------------------
//  Comprueba el estado de la cuenta. Devuelve EstadoCuenta::Ok si puede entrar.
//  El ORDEN de las comprobaciones decide qué motivo de rechazo gana.
// ----------------------------------------------------------------------------
EstadoCuenta ServidorLogin::evaluarEstado(const Conexion& con,
                                          const std::string& hashRecibidoHex,
                                          uint64_t claveActual) {
    const Cuenta& c = con.cuenta;
    uint32_t ahora = static_cast<uint32_t>(time(nullptr));

    // 1) Mantenimiento: rechaza a todos menos a los GameMasters.
    if (cfg().mantenimiento && c.nivelGm == 0)
        return EstadoCuenta::EnMantenimiento;

    // 2) ¿Existe la cuenta?
    if (!c.encontrada)
        return EstadoCuenta::NoExiste;

    // 3) Ban permanente.
    if (c.baneada)
        return EstadoCuenta::Baneada;

    // 4) Ban temporal (hasta una fecha futura).
    if (c.baneadaHasta != 0 && c.baneadaHasta > ahora)
        return EstadoCuenta::BaneadaTemporal;

    // 5) Contraseña.
    //    El cliente "sala" el hash cada sesión: cambian los bytes en las
    //    posiciones 0,4,8,... pero el resto (15 de 21) son estables para una
    //    misma contraseña, y la LONGITUD cambia con la contraseña. Por eso
    //    comparamos con contrasenaCoincide(), que ignora los bytes salados:
    //    una contraseña correcta coincide en los bytes estables; una incorrecta
    //    cambia de longitud o de bytes estables -> se rechaza.
    if (!c.hashContrasena.empty()) {
        // Hay hash de referencia en la base de datos: validamos SIEMPRE.
        if (!contrasenaCoincide(hashRecibidoHex, c.hashContrasena))
            return EstadoCuenta::ContrasenaIncorrecta;
    } else if (cfg().exigirContrasena) {
        // Sin hash guardado: solo rechazamos si exiges contraseña a todas las
        // cuentas (si no, se permite y ya se registró el hash para guardarlo).
        return EstadoCuenta::ContrasenaIncorrecta;
    }

    // 6) Tiempo de juego / suscripción caducada.
    if (c.suscripcionHasta != 0 && c.suscripcionHasta < ahora)
        return EstadoCuenta::SinTiempoDeJuego;

    // 7) Sesión duplicada.
    if (cuentaYaConectada(c.id, claveActual))
        return EstadoCuenta::YaConectada;

    return EstadoCuenta::Ok;
}

// ----------------------------------------------------------------------------
//  Envía LOGINREJECTED (opcode 0x138a) con el código del estado.
//  El código 7 (ban temporal) lleva además el timestamp de fin del ban.
// ----------------------------------------------------------------------------
void ServidorLogin::enviarRechazo(Conexion& con, const udp::endpoint& remoto,
                                  EstadoCuenta estado) {
    uint8_t codigo = estadoARechazo(estado);

    // appData = [opcode 0x138a][codigo:1] (+[timestamp:4] si es ban temporal).
    uint8_t a[2 + 1 + 4];
    escribir16(a, op::LOGINRECHAZADO);
    a[2] = codigo;
    int longApp = 2 + 1;

    if (estado == EstadoCuenta::BaneadaTemporal) {
        escribir32(a + 3, con.cuenta.baneadaHasta); // fecha de fin del ban
        longApp = 2 + 1 + 4;
    }

    uint8_t m[64];
    int ml = pr::componerMensajeApp(m, con.idConexion, a, longApp);
    enviarFiable(con, remoto, m, ml);
    registro::log("   -> 0x138a LOGINREJECTED codigo=%u (%s)", codigo, nombreEstado(estado));
}

} // namespace prison
