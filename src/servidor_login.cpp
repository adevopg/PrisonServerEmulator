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
#include "prison/cifrado.hpp"
#include "prison/utilidades.hpp"
#include "prison/registro.hpp"

#include <windows.h>   // Sleep, getenv vía CRT
#include <cstring>
#include <cstdlib>
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
        if (const char* fe = getenv("START_FIELDC"))
            c.idMensajeTx = static_cast<uint32_t>(atoi(fe) - 1);

        // Autenticar contra MySQL.
        Cuenta cuenta = bd_.buscarCuenta(usuario);
        c.idCuenta = cuenta.id;
        registro::log("   MySQL: usuario='%s' -> %s idCuenta=%u",
                      usuario.c_str(), cuenta.encontrada ? "ENCONTRADA" : "NO ENCONTRADA", c.idCuenta);
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
        registro::volcadoHex("   tx:", r, sizeof r);
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
    if (K && plen > 0) {
        cifrado::descifrar(pay, plen, K);
        registro::volcadoHex("   datos (descifrados):", pay, plen);
    } else {
        registro::volcadoHex("   datos (en claro):", pay, plen);
    }

    // El opcode de aplicación está en el offset 0x14 del payload descifrado.
    //   0x1388 = LOGIN, 0x13a1 = latido (heartbeat).
    if (!(K && plen >= pr::TAM_CABECERA && it != conexiones_.end())) return;

    Conexion& con = it->second;
    uint16_t opcode = leer16(pay + 0x14);
    registro::log("   opcode app = 0x%04x%s", opcode,
                  opcode == op::LOGIN ? " (LOGIN)" : opcode == op::LATIDO ? " (latido)" : "");

    // -------------------- LOGIN (0x1388) --------------------
    // Respondemos con la estructura de cuenta (opcode 0x1389) fragmentada.
    // (El cliente hace `dec` en su dispatch, por eso el handler 0x40a59e es 0x1389.)
    if (opcode == op::LOGIN && !con.enviadoLogin) {
        con.enviadoLogin = true;
        registro::log("   *** LOGIN '%s' (%s) -> cuenta 0x1389 (fragmentada) ***",
                      con.usuario.c_str(), con.idCuenta ? "ENCONTRADA" : "DESCONOCIDA");

        static uint8_t app[2 + 0x9cd];
        memset(app, 0, sizeof app);
        escribir16(app, op::CUENTA);                            // handler de cuenta 0x40a59e
        escribir32(app + 2, con.idCuenta ? con.idCuenta : 1);   // idCuenta en struct[0]
        app[2 + 4] = 1;                                         // struct+4 = nº de personajes = 1

        // --- Personaje en la ranura 0 (real, para que la lista lo muestre) ---
        // Offsets relativos al slot del personaje (render char-select 0x5482ff).
        uint8_t* ch = app + 2 + 7;                  // base del slot 0 del personaje
        ch[0x00] = 1;                               // +0 = marca "existe" (!=0)
        const char* nombrePj = "Innamine";
        memcpy(ch + 2, nombrePj, strlen(nombrePj)); // +2 = NOMBRE (asciiz)
        ch[0x29] = 0;                               // +0x29 = flag selección de nombre de clase
        ch[0x40] = 0;                               // +0x40 = índice de clase (0 -> "Recluso")
        escribir32(ch + 0x34, 1000);               // +0x34 = pos X (el render divide entre [+0x34]*10; 0 -> crash)
        escribir32(ch + 0x38, 1000);               // +0x38 = pos Y
        escribir32(ch + 0x51, 0xFFFFFFFFu);        // +0x51 -> suprime el auto-enter 0x139f
        escribir32(ch + 0x65, 1);                  // +0x65 = id de prisión/servidor (= game_servers id 1)
        ch[0x69] = 10;                             // +0x69 = nivel (se muestra +1 = 11)
        ch[0x6a] = 0;                              // +0x6a = estado/tipo (0..3)
        // +0x6d (nº de objetos) queda 0 -> sin arrays de inventario.

        enviarFragmentado(con, remoto, app, 2 + 0x9cd);
    }
    // -------------------- CREAR PERSONAJE (0x1394) --------------------
    // El cliente envía nick + atributos + aspecto al pulsar CONTINUAR.
    // Respondemos CHARCREATED (0x1395). El nick va asciiz en pay+0x16.
    else if (opcode == op::CREAR_PERSONAJE) {
        char nick[24] = {0};
        if (plen > 0x16) {
            const char* p = reinterpret_cast<const char*>(pay + 0x16);
            for (int i = 0; i < static_cast<int>(sizeof nick) - 1 && 0x16 + i < plen && p[i]; i++)
                nick[i] = p[i];
        }
        if (!nick[0]) strcpy(nick, "Recluso");
        registro::log("   *** CREAR PERSONAJE nick='%s' -> CHARCREATED (0x1395) ***", nick);

        static uint8_t cca[2 + 1 + 0x342];
        memset(cca, 0, sizeof cca);
        escribir16(cca, op::CHARCREATED);         // CHARCREATED
        cca[2] = 0;                               // índice de personaje 0
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

        // Lista de servidores RICA (opcional, env RICH_LIST): nombre + reclusos + .skf, comprimida.
        if (getenv("RICH_LIST")) {
            uint8_t blob[256]; int bi = 0;
            const char* nm = getenv("PRISON_NAME"); if (!nm) nm = "La Prision";
            int nl = (int)strlen(nm); memcpy(blob + bi, nm, nl); bi += nl; blob[bi++] = 0;
            uint32_t reclusos = getenv("RECLUSOS") ? (uint32_t)atoi(getenv("RECLUSOS")) : 42;
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
        if (getenv("CLASSINFO")) {
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

        // --- Servidores de mundo desde MySQL (mínimo 2 para que la lista no auto-avance) ---
        uint32_t srvIds[2] = {1, 2};
        char     srvNombre[2][128] = {"La Prision - Local", "La Prision II"};
        uint8_t  srvReclu[2] = {0, 0};
        {
            auto servidores = bd_.listarServidores(2);
            for (size_t e = 0; e < servidores.size() && e < 2; e++) {
                srvIds[e] = servidores[e].id;
                strncpy(srvNombre[e], servidores[e].nombre.c_str(), 127);
                srvNombre[e][127] = 0;
                uint32_t pop = servidores[e].poblacion;
                srvReclu[e] = (uint8_t)(pop > 255 ? 255 : pop);
            }
        }

        // SERVERADDED (0x13a9): crea el nodo de cada prisión con su nombre mostrado.
        {
            uint8_t sv[400]; int si = 0;
            escribir16(sv, op::SERVERADDED); si = 2;
            escribir16(sv + si, 2); si += 2;             // count = 2
            for (int e = 0; e < 2; e++) {
                escribir32(sv + si, srvIds[e]); si += 4; // id
                sv[si++] = 2;                            // flag
                escribir32(sv + si, 0); si += 4;         // dword -> node+8
                int pl = (int)strlen(srvNombre[e]); memcpy(sv + si, srvNombre[e], pl); si += pl; sv[si++] = 0; // nombre
                sv[si++] = 0;                            // str2 (vacío)
            }
            uint8_t m[460];
            int ml = pr::componerMensajeApp(m, con.idConexion, sv, si);
            enviarFiable(con, remoto, m, ml);
            registro::log("   -> 0x13a9 SERVERADDED x2 ('%s','%s')", srvNombre[0], srvNombre[1]);
        }

        // AVAILABLESERVERS (0x13ac): el byte de LONGITUD por entrada ES el número
        // de "reclusos" mostrado. Su "nombre" UTF-16 de esa longitud es relleno.
        {
            uint8_t data[2 * (5 + 2 * 255)]; int di = 0;
            for (int e = 0; e < 2; e++) {
                uint8_t cuenta = srvReclu[e];
                escribir32(data + di, srvIds[e]); di += 4; data[di++] = cuenta;
                for (int k = 0; k < cuenta; k++) { data[di++] = ' '; data[di++] = 0; } // relleno UTF-16
            }
            uint8_t sv[8 + sizeof(data)]; int si = 0;
            escribir16(sv, op::AVAILABLESERVERS); si = 2; sv[si++] = 2; escribir32(sv + si, (uint32_t)di); si += 4;
            memcpy(sv + si, data, di); si += di;
            uint8_t smsg[24 + sizeof(sv)];
            int smlen = pr::componerMensajeApp(smsg, con.idConexion, sv, si);
            enviarFiable(con, remoto, smsg, smlen);
            registro::log("   -> 0x13ac AVAILABLESERVERS reclusos=[%u,%u]", srvReclu[0], srvReclu[1]);
        }
        registro::log("   -> 0x13d5(aceptar)+0x13ac(servidores)");
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
    else if (opcode == op::SELECCIONAR && con.enviadoLogin && !con.enviadoEntrar && getenv("ENTER_GAME")) {
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

} // namespace prison
