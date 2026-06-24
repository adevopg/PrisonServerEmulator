// ============================================================================
//  servidor_mundo.cpp  —  Implementación del servidor de MUNDO (ver .hpp)
// ============================================================================
//
//  ATENCIÓN: lógica byte a byte de ingeniería inversa. Los comentarios indican
//  direcciones del cliente (ej: 0x40fef5). La aparición del jugador (SPAWN)
//  está controlada por variables de entorno y sigue en investigación.
// ============================================================================
#include "prison/servidor_mundo.hpp"
#include "prison/protocolo_sns.hpp"
#include "prison/opcodes.hpp"
#include "prison/configuracion.hpp"
#include "prison/cifrado.hpp"
#include "prison/utilidades.hpp"
#include "prison/registro.hpp"
#include "prison/monitor.hpp"
#include "prison/nombres_objeto.hpp"

#include <windows.h>   // Sleep
#include <cstring>
#include <cstdlib>
#include <string>

namespace prison {

using boost::asio::ip::udp;
namespace pr = prison::protocolo;

ServidorMundo::ServidorMundo(boost::asio::io_context& io)
    : ServidorUdp(io, "MUNDO", pr::PUERTO_MUNDO) {
    contadorMarcaTiempo_ = 0x55667788; // valor inicial original del mundo
}

// ----------------------------------------------------------------------------
//  prepararContenido(): construye el OBJECTINFO UNA vez (al arrancar).
//
//  El servidor original carga y comprime la tabla de objetos al iniciarse y
//  registra los tamanos ("Compressed Objectinfo size ...", "Objectinfo creado.").
//  Antes nosotros recompriamos esto en CADA spawn de cliente: ineficiente y
//  distinto al original. Ahora se hace una sola vez y se cachea en objInfo_.
//
//  Formato (descomprimido), parseado por el loader 0x587df0:
//    [N:u16] N strings de categoria
//    [M:u32] M defs ; por def: [id:u16][nameLen:u8][name\0][28 bytes][len3:u8=0]
// ----------------------------------------------------------------------------
void ServidorMundo::prepararContenido() {
    const int NOBJ = 256;
    static uint8_t op[16384]; int o = 0;
    escribir16(op + o, 1); o += 2;                 // N = 1 categoria
    op[o++] = 4; memcpy(op + o, "obj", 4); o += 4; // categoria[0] = "obj\0"
    escribir32(op + o, NOBJ); o += 4;              // M = nº de defs
    const int NN = (int)(sizeof NOMBRES_OBJETO / sizeof NOMBRES_OBJETO[0]);
    for (int id = 0; id < NOBJ; id++) {
        const char* nm = (id < NN) ? NOMBRES_OBJETO[id] : "Objeto";
        int L = (int)strlen(nm) + 1;               // incluye el \0
        escribir16(op + o, (uint16_t)id); o += 2;  // def id
        op[o++] = (uint8_t)L;                      // nameLen
        memcpy(op + o, nm, L); o += L;             // nombre real + \0
        memset(op + o, 0, 28); o += 28;            // cabecera de def (28B) a cero
        op[o++] = 0;                               // len3 = 0 (sub-array vacio)
    }
    static uint8_t z[16384]; int zl = cifrado::comprimirZlib(z, op, o);

    objInfo_.resize(10 + zl);
    escribir16(objInfo_.data(),     op::OBJECTINFO);
    escribir32(objInfo_.data() + 2, (uint32_t)o);   // tamano descomprimido
    escribir32(objInfo_.data() + 6, (uint32_t)zl);  // tamano comprimido
    memcpy   (objInfo_.data() + 10, z, zl);

    registro::log("Uncompressed Objectinfo size %d", o);
    registro::log("Compressed Objectinfo size %d", zl);
    registro::log("Objectinfo creado.");

    // ---- Helper: envuelve un buffer (ya descomprimido) como mensaje de tabla
    // de sala [opcode:2][uncompSize:4][compSize:4][zlib] y lo cachea. Devuelve
    // (uncomp, comp) para los logs. Mismo formato/decompresor que OBJECTINFO. ----
    auto construir = [](std::vector<uint8_t>& dst, uint16_t opcode,
                        const uint8_t* datos, int nd) -> std::pair<int,int> {
        uint8_t zz[4096];
        int zc = cifrado::comprimirZlib(zz, datos, nd);
        dst.resize(10 + zc);
        escribir16(dst.data(),     opcode);
        escribir32(dst.data() + 2, (uint32_t)nd);
        escribir32(dst.data() + 6, (uint32_t)zc);
        memcpy   (dst.data() + 10, zz, zc);
        return {nd, zc};
    };

    // ---- SUPPLIESINFO (0x13a6): tabla vacia. El parser 0x4a0000 lee el numero
    // de entradas en el word de offset 2; con 0 no recorre nada. (4 bytes) ----
    {
        uint8_t sup[4] = {0, 0, 0, 0};   // [word0=0][count=0]
        auto sz = construir(suppliesInfo_, op::SUPPLIESINFO, sup, sizeof sup);
        registro::log("Uncompressed supplyinfo size %d", sz.first);
        registro::log("Compressed supplyinfo size %d",   sz.second);
    }

    // ---- BOTSINFO/NPCInfo (0x13a7): tabla vacia. El parser 0x4a03c0 lee el
    // numero de NPCs en el word de offset 0; con 0 no recorre nada. (2 bytes) ----
    {
        uint8_t bot[2] = {0, 0};         // [count=0]
        auto sz = construir(botsInfo_, op::BOTSINFO, bot, sizeof bot);
        registro::log("Uncompressed botinfos size %d", sz.first);
        registro::log("Compressed botinfos size %d",   sz.second);
    }

    // ---- QUESTSINFO (0x14ee): tabla vacia. El parser 0x49fb30 lee el numero de
    // misiones en el dword de offset 0; con 0 no recorre nada. (4 bytes) ----
    {
        uint8_t q[4] = {0, 0, 0, 0};     // [count:u32 = 0]
        construir(questsInfo_, op::QUESTSINFO, q, sizeof q);
    }

    // NOTA: BOXESINFO (0x13a4) se construye pero NO se usa en la secuencia de
    // SPAWN porque su parser depende de la sala (global [0x5ed9b4]) que aun no
    // existe; ver la nota en el envio. Queda documentado para el futuro.

    // ---- COSMÉTICO (no es red): "rutas" es el pathfinding interno del servidor
    // y "modulos" los carga el propio cliente de sus ficheros locales
    // (DATA\NUEVO\MAPA\MODULO*.pcx). No hay datos que enviar; se registran para
    // que la consola se parezca a la del servidor original. ----
    registro::log("Cargando 1645 rutas...");
    registro::log("Rutas cargadas.");
    registro::log("Creando modulos...");
    registro::log("16 Modulos creados.");
}

void ServidorMundo::procesarPaquete(uint8_t* buf, int n, const udp::endpoint& remoto) {
    if (n < pr::TAM_CABECERA) return;

    std::string ip = remoto.address().to_string();
    uint16_t puertoRemoto = remoto.port();

    uint32_t connLo = leer32(buf + pr::OFF_CONN_LO);
    uint16_t flags  = leer16(buf + pr::OFF_FLAGS);
    uint16_t secuencia = leer16(buf + pr::OFF_SECUENCIA);
    uint16_t tipo   = leer16(buf + pr::OFF_TIPO);
    uint32_t nonce  = (n >= 0x1e) ? leer32(buf + pr::OFF_NONCE) : 0;
    bool esHandshake = (connLo == pr::CONN_HANDSHAKE);
    uint64_t clave = claveDeConexion(remoto);

    registro::log("[MUNDO] <- %s:%u len=%d %s flags=%u seq=%u tipo=%u",
                  ip.c_str(), puertoRemoto, n, esHandshake ? "HS" : "DATOS", flags, secuencia, tipo);

    // ===================== HANDSHAKE =====================
    if (esHandshake && tipo == pr::TIPO_SYN) {
        std::string usuario;
        if (n > pr::OFF_DATOS) {
            usuario.assign(reinterpret_cast<const char*>(buf + pr::OFF_DATOS),
                           static_cast<size_t>(n - pr::OFF_DATOS));
            size_t z = usuario.find('\0');
            if (z != std::string::npos) usuario.resize(z);
        }
        Conexion c;
        c.idConexion = siguienteId_++;
        c.clave = 0xA5A5A5A5u ^ static_cast<uint32_t>(clave);
        c.fase = Fase::SynRespondido;
        c.usuario = usuario;
        conexiones_[clave] = c;

        uint32_t K = c.clave, TS = contadorMarcaTiempo_++;
        uint32_t f1 = ((TS ^ K) & pr::MASCARA_CLAVE) ^ K;
        uint32_t f2 = ((TS ^ K) & pr::MASCARA_CLAVE) ^ TS;

        uint8_t r[34]; memset(r, 0, sizeof r);
        escribir32(r + pr::OFF_CONN_LO, 0xFFFFFFFFu);
        escribir32(r + pr::OFF_CONN_HI, 0xFFFFFFFFu);
        r[pr::OFF_VENTANA] = 1;
        escribir32(r + pr::OFF_CAMPO_C, f2);
        escribir32(r + pr::OFF_MARCA_TIEMPO, f1);
        escribir16(r + pr::OFF_SECUENCIA, secuencia);
        escribir16(r + pr::OFF_TIPO, pr::TIPO_SYN_ACK);
        escribir16(r + pr::OFF_CONST, 4);
        escribir32(r + pr::OFF_NONCE, nonce);
        escribir32(r + pr::OFF_DATOS, c.idConexion);
        enviar(r, sizeof r, remoto);
        registro::log("   [MUNDO] SYN usuario='%s' -> SYN-ACK idConexion=%08x", usuario.c_str(), c.idConexion);
        return;
    }

    if (esHandshake && tipo == pr::TIPO_ACK) {
        auto it = conexiones_.find(clave);
        if (it != conexiones_.end()) {
            it->second.fase = Fase::Establecida;
            registro::log("   [MUNDO] ESTABLECIDA usuario='%s'", it->second.usuario.c_str());
        }
        return;
    }

    // Tipo 4 = cierre (FIN) -> responder tipo 5 (FIN-ACK), igual que el login.
    if (esHandshake && tipo == 4) {
        uint8_t r[64];
        int len = (n < static_cast<int>(sizeof r)) ? n : static_cast<int>(sizeof r);
        memcpy(r, buf, len);
        escribir16(r + pr::OFF_TIPO, 5);
        enviar(r, len, remoto);
        conexiones_.erase(clave);
        monitor::clienteSale(clave);
        registro::log("   [MUNDO] handshake tipo4 (FIN) -> tipo5 (FIN-ACK), cierro conexión");
        return;
    }

    if (esHandshake) return;

    // ===================== FASE DE DATOS =====================
    auto it = conexiones_.find(clave);
    uint32_t miConn = (it != conexiones_.end()) ? it->second.idConexion : connLo;

    // ACK si lo pide.
    if (flags & pr::FLAG_PIDE_ACK) {
        uint8_t r[pr::TAM_CABECERA]; memset(r, 0, sizeof r);
        escribir32(r + pr::OFF_CONN_LO, 1);
        escribir32(r + pr::OFF_CONN_HI, miConn);
        escribir16(r + pr::OFF_FLAGS, pr::FLAG_ES_ACK);
        r[pr::OFF_VENTANA] = 1;
        memcpy(r + pr::OFF_CAMPO_C,      buf + pr::OFF_CAMPO_C, 4);
        memcpy(r + pr::OFF_MARCA_TIEMPO, buf + pr::OFF_MARCA_TIEMPO, 4);
        memcpy(r + pr::OFF_SECUENCIA,    buf + pr::OFF_SECUENCIA, 2);
        enviar(r, sizeof r, remoto);
    }

    int plen = n - pr::OFF_PAYLOAD;
    uint8_t* pay = buf + pr::OFF_PAYLOAD;
    uint32_t K = (it != conexiones_.end()) ? it->second.clave : 0;
    if (!(K && plen > 0)) return;

    cifrado::descifrar(pay, plen, K);
    uint16_t opcode = (plen >= 0x16) ? leer16(pay + 0x14) : 0;
    bool esPing = (plen >= 18 && leer16(pay + 8) == op::PING);
    registro::log("   [MUNDO] datos plen=%d opcodeApp=0x%04x%s", plen, opcode,
                  esPing ? " (ping)" : opcode == op::PASSDOOR ? " (PASSDOOR)" : "");

    // Solo volcamos el hex de lo que aún no conocemos.
    if (!esPing && opcode != op::PASSDOOR)
        registro::volcadoHex("   [MUNDO] datos del opcode desconocido:", pay, plen > 128 ? 128 : plen);

    if (it != conexiones_.end())
        procesarDatos(buf, n, remoto, flags, opcode);
}

void ServidorMundo::procesarDatos(uint8_t* buf, int n, const udp::endpoint& remoto,
                                  uint16_t /*flags*/, uint16_t opcode) {
    uint64_t clave = claveDeConexion(remoto);
    auto it = conexiones_.find(clave);
    if (it == conexiones_.end()) return;
    Conexion& con = it->second;

    int plen = n - pr::OFF_PAYLOAD;
    uint8_t* pay = buf + pr::OFF_PAYLOAD;

    // -------------------- PING / PONG (opcode de control 9) --------------------
    // El cliente envía un PING cada ~2s. DEBEMOS reenviar (echo) ese mensaje
    // verbatim: es lo ÚNICO que resetea su "última actividad" (0x5edd64). Si no
    // lo hacemos, el ping sube y el cliente se desconecta a los ~5s de entrar.
    // El mensaje de control va "envuelto una sola vez", así que su appMsg está
    // en pay+8 (a diferencia de los mensajes >=0x1388 que van en pay+0x14).
    if (plen >= 18 && leer16(pay + 8) == op::PING) {
        int amLen = plen - 8; if (amLen > 64) amLen = 64;
        uint8_t am[64]; memcpy(am, pay + 8, amLen);
        // El cliente dibuja el número de ping solo si RTT > 0. En localhost el eco
        // es tan rápido que RTT redondea a 0 y el número parpadea. Atrasamos el
        // timestamp unas unidades para que RTT sea siempre un valor pequeño > 0.
        if (amLen >= 10) { uint32_t ts = leer32(am + 6); escribir32(am + 6, ts - 3); }
        uint8_t m[128]; int ml = pr::componerMensajeApp(m, con.idConexion, am, amLen);
        enviarFiable(con, remoto, m, ml);
        registro::log("   [MUNDO] PONG eco op9 amLen=%d", amLen);
    }

    // -------------------- SPAWN (aparición del jugador) --------------------
    // Cuando el cliente envía PASSDOOR (opcode 0x138e) y SPAWN está activado por
    // entorno, enviamos toda la secuencia de aparición. Sigue en investigación.
    if (opcode == op::PASSDOOR && !con.enviadoAceptar && cfg().spawn) {
        con.enviadoAceptar = true;
        uint32_t pid = cfg().idJugador;

        // ---- Configuración de sala/mapa/objetos (ROOM) ----
        if (cfg().room) {
            uint32_t tmpl = cfg().plantilla;

            // SERVERPARAMS (0x139e): reserva globales de sesión + configura los
            // temporizadores de ping. PingTime=0 era el bug (sin ping -> caída).
            {
                uint8_t sp[2 + 0x40]; memset(sp, 0, sizeof sp);
                escribir16(sp, op::SERVERPARAMS);
                escribir16(sp + 6, 15);     // LinkProblems = 15s
                escribir16(sp + 8, 60);     // LinkDropped  = 60s
                escribir32(sp + 10, 2000);  // PingTime => el cliente hace ping cada ~2s
                uint8_t m[0x200]; int ml = pr::componerMensajeApp(m, con.idConexion, sp, 2 + 0x40);
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** SERVERPARAMS 0x139e (PingTime=2000) ***");
                Sleep(80);
            }

            // MAPINFO (0x13a5): define plantillas de sala. Payload zlib =
            //   [count:2][ id:4, nombre1\0, nombre2\0, subcount:2 ].
            {
                const char* mapnm = cfg().nombreMapa.c_str();
                uint8_t up[256]; int u = 0;
                int mnl = (int)strlen(mapnm);
                escribir16(up + u, 1); u += 2;                  // count = 1 plantilla
                escribir32(up + u, tmpl); u += 4;               // id de plantilla
                memcpy(up + u, mapnm, mnl + 1); u += mnl + 1;   // nombre1
                memcpy(up + u, mapnm, mnl + 1); u += mnl + 1;   // nombre2 = nombre del mapa
                escribir16(up + u, 0); u += 2;                  // subcount = 0
                uint8_t z[512]; int zl = cifrado::comprimirZlib(z, up, u);
                uint8_t mi[700];
                escribir16(mi, op::MAPINFO); escribir32(mi + 2, u); escribir32(mi + 6, zl); memcpy(mi + 10, z, zl);
                uint8_t m[900]; int ml = pr::componerMensajeApp(m, con.idConexion, mi, 10 + zl);
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** MAPINFO 0x13a5 tmpl=%u map=%s ***", tmpl, mapnm);
                Sleep(80);
            }

            // OBJECTINFO (0x13a8): tabla de objetos/items ([0x5ed334]). Ya viene
            // construido y comprimido desde prepararContenido() (una sola vez al
            // arrancar, como el original); aqui solo se envia el blob cacheado.
            {
                if (objInfo_.empty()) prepararContenido();   // por si acaso
                static uint8_t m[10 + 16384 + 64];
                int ml = pr::componerMensajeApp(m, con.idConexion,
                                                objInfo_.data(), (int)objInfo_.size());
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** OBJECTINFO 0x13a8 enviado (%d bytes) ***",
                              (int)objInfo_.size());
                Sleep(80);
            }

            // BOTSINFO (0x13a7) y SUPPLIESINFO (0x13a6): tablas vacias pero
            // VALIDAS (0 NPCs / 0 supplies). El cliente las parsea de verdad
            // ("NPCs Info leeched [0]"). Cacheadas en prepararContenido().
            {
                if (botsInfo_.empty()) prepararContenido();
                uint8_t m[256];
                int ml = pr::componerMensajeApp(m, con.idConexion,
                                                botsInfo_.data(), (int)botsInfo_.size());
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** BOTSINFO 0x13a7 enviado (%d bytes) ***",
                              (int)botsInfo_.size());
                Sleep(80);
            }
            {
                uint8_t m[256];
                int ml = pr::componerMensajeApp(m, con.idConexion,
                                                suppliesInfo_.data(), (int)suppliesInfo_.size());
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** SUPPLIESINFO 0x13a6 enviado (%d bytes) ***",
                              (int)suppliesInfo_.size());
                Sleep(80);
            }
            {
                uint8_t m[256];
                int ml = pr::componerMensajeApp(m, con.idConexion,
                                                questsInfo_.data(), (int)questsInfo_.size());
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** QUESTSINFO 0x14ee enviado (%d bytes) ***",
                              (int)questsInfo_.size());
                Sleep(80);
            }
            // NOTA: BOXESINFO (0x13a4) NO se envia aqui. Su parser (0x4af800) usa
            // el global de sala [0x5ed9b4], que todavia es NULL en este punto
            // (la sala se crea con ROOMPARAMS, despues). Enviarlo aqui crashea el
            // cliente al loguear con %s sobre la sala nula. Ademas no hace falta:
            // sin BOXESINFO el cliente deja las cajas vacias por defecto.

            // ROOMPARAMS (opcode 0): sala + mapa.
            {
                int msel = cfg().mapa;
                uint32_t rid = cfg().idSala;
                uint8_t r0[4 + 0x30]; memset(r0, 0, sizeof r0);
                escribir16(r0, op::ROOMPARAMS);  // opcode 0 = ROOMPARAMS
                escribir16(r0 + 2, 1);      // room_id (cabecera)
                r0[4] = (uint8_t)msel;      // room_data[0] = selector de mapa
                escribir32(r0 + 14, rid);   // room_data[10] = RoomID
                escribir32(r0 + 18, tmpl);  // room_data[14] = plantilla (= id de MAPINFO)
                uint8_t m[0x200]; int ml = pr::componerMensajeApp(m, con.idConexion, r0, 4 + 0x30);
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** ROOMPARAMS op0 map=0x%02x rid=%u tmpl=%u ***", msel, rid, tmpl);
                Sleep(80);
            }
        }

        // ---- opcode 2: CREAR jugador local ----
        {
            const char* nm = cfg().nombreJugador.c_str();
            int L = (int)strlen(nm);
            int posz = cfg().tamPosicion;
            uint8_t c2[2 + 96 + 8 + 0x280]; memset(c2, 0, sizeof c2); int o = 0;
            escribir16(c2 + o, op::CREAR_JUGADOR); o += 2; // opcode 2
            memcpy(c2 + o, nm, L + 1); o += L + 1;        // nombre + NUL
            escribir32(c2 + o, pid); o += 4;             // id
            escribir32(c2 + o, 0);   o += 4;
            memset(c2 + o, 0, posz); o += posz;          // bloque de posición
            uint8_t m[0x300]; int ml = pr::componerMensajeApp(m, con.idConexion, c2, o);
            enviarFiable(con, remoto, m, ml);
            registro::log("   [MUNDO] *** SPAWN op2 CREAR name=%s id=%u ***", nm, pid);
            monitor::clienteEntra(clave, con.idConexion, nm, cfg().nombreMapa);  // -> lista Players de la GUI
            Sleep(60);
        }

        // ---- opcode 3: ACTUALIZAR jugador + ENTRAR (puerta = 0xff) ----
        {
            int pdz = cfg().tamDatosJug;
            uint8_t c3[2 + 4 + 0x280]; memset(c3, 0, sizeof c3);
            escribir16(c3, op::ENTRAR); // opcode 3
            escribir32(c3 + 2, pid);    // id (clave de búsqueda)
            c3[0x16] = 0xff;            // bloque_datos[0x10] = puerta = 0xff
            uint8_t m[0x300]; int ml = pr::componerMensajeApp(m, con.idConexion, c3, 6 + pdz);
            enviarFiable(con, remoto, m, ml);
            registro::log("   [MUNDO] *** SPAWN op3 ENTRAR id=%u puerta=0xff ***", pid);
            Sleep(80);
        }

        // ---- opcode 6: ROOMREADY (finaliza la sala y da el control al jugador) ----
        {
            uint8_t r6[2]; escribir16(r6, op::ROOMREADY);
            uint8_t m[64]; int ml = pr::componerMensajeApp(m, con.idConexion, r6, 2);
            enviarFiable(con, remoto, m, ml);
            registro::log("   [MUNDO] *** ROOMREADY op6 ***");
        }
    }
    // -------------------- BARRIDO DE OPCODES (diagnóstico, sin SPAWN) --------------------
    // Envía opcodes candidatos uno a uno para ver cuáles reconoce el cliente
    // (lo anota en networkdebug.txt). Rango por variables de entorno.
    else if (opcode == op::PASSDOOR && !con.enviadoAceptar) {
        con.enviadoAceptar = true;
        int lo = cfg().barridoDesde;
        int hi = cfg().barridoHasta;
        int dly = cfg().barridoMs;
        registro::log("   [MUNDO] *** BARRIDO 0x%04x..0x%04x (%dms cada uno) ***", lo, hi, dly);
        for (int wop = lo; wop <= hi; wop++) {
            uint8_t a[2 + 16]; escribir16(a, (uint16_t)wop);
            memset(a + 2, 0, 16);
            uint8_t m[64]; int ml = pr::componerMensajeApp(m, con.idConexion, a, 2 + 16);
            enviarFiable(con, remoto, m, ml);
            registro::log("   [MUNDO] barrido op=0x%04x", wop);
            Sleep(dly);
        }
        registro::log("   [MUNDO] *** BARRIDO COMPLETADO ***");
    }
}

} // namespace prison
