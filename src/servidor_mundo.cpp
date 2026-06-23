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
    registro::log("   [MUNDO] datos plen=%d opcodeApp=0x%04x", plen, opcode);
    registro::volcadoHex("   [MUNDO] datos (descifrados):", pay, plen > 128 ? 128 : plen);

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
                uint8_t z[512]; int zl = cifrado::comprimirZlibStored(z, up, u);
                uint8_t mi[700];
                escribir16(mi, op::MAPINFO); escribir32(mi + 2, u); escribir32(mi + 6, zl); memcpy(mi + 10, z, zl);
                uint8_t m[900]; int ml = pr::componerMensajeApp(m, con.idConexion, mi, 10 + zl);
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** MAPINFO 0x13a5 tmpl=%u map=%s ***", tmpl, mapnm);
                Sleep(80);
            }

            // OBJECTINFO (0x13a8): tabla de definiciones de objetos/items.
            {
                uint8_t op[256]; int o = 0;
                escribir16(op + o, 1); o += 2;               // nameCount = 1
                op[o++] = 4; memcpy(op + o, "obj", 4); o += 4; // name[0] = "obj\0"
                escribir32(op + o, 1); o += 4;               // defCount = 1
                escribir16(op + o, 0xff); o += 2;            // def id = 0xff (cubre ids 0..255)
                op[o++] = 0;                                 // longitud de nombre de def = 0
                memset(op + o, 0, 0x80); o += 0x80;          // datos de def: ceros
                uint8_t z[256]; int zl = cifrado::comprimirZlibStored(z, op, o);
                uint8_t oi[2 + 8 + 256];
                escribir16(oi, op::OBJECTINFO); escribir32(oi + 2, o); escribir32(oi + 6, zl); memcpy(oi + 10, z, zl);
                uint8_t m[400]; int ml = pr::componerMensajeApp(m, con.idConexion, oi, 10 + zl);
                enviarFiable(con, remoto, m, ml);
                registro::log("   [MUNDO] *** OBJECTINFO 0x13a8 ***");
                Sleep(80);
            }

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
