// ============================================================================
//  opcodes.hpp  —  Nombres de TODOS los opcodes del protocolo de aplicación
// ============================================================================
//
//  ¿PARA QUÉ SIRVE?
//
//  Un "opcode" es el número que identifica QUÉ tipo de mensaje es (login,
//  latido, crear personaje, etc.). En la red viajan como números crudos
//  (0x1388, 0x13a1...) que no dicen nada. Este archivo les pone NOMBRE para
//  que el código se entienda:
//
//        if (opcode == op::LOGIN)        en vez de   if (opcode == 0x1388)
//
//  El opcode va en el offset 0x14 del payload descifrado (mensajes de login)
//  o al principio del payload (mensajes pequeños de control del mundo).
//
//  ─────────────────────────────────────────────────────────────────────────
//  NOTA IMPORTANTE (desfase de +1):
//  El cliente, al recibir, hace un "dec" (resta 1) antes de buscar el manejador.
//  Por eso el opcode que ENVÍA el servidor suele ser la etiqueta del manejador
//  del cliente. Ej: el manejador de cuenta es 0x40a59e (etiqueta 0x1389), así
//  que el servidor ENVÍA 0x1389; JUGAR tiene etiqueta 0x13f1 y el servidor
//  responde ENVIANDO 0x13f2. Esto está reflejado en los nombres de abajo.
//  ─────────────────────────────────────────────────────────────────────────
// ============================================================================
#pragma once

#include <cstdint>

namespace prison {
namespace op {

// ===========================================================================
//  1) CLIENTE  ->  SERVIDOR   (lo que el cliente nos envía, en el LOGIN)
// ===========================================================================
enum OpcodeCliente : uint16_t {
    CONECTAR_CONFIRMA = 0x0000, // confirmación de conexión (sin datos útiles)
    LOGIN             = 0x1388, // pide iniciar sesión (tras el handshake)
    CREAR_PERSONAJE   = 0x1394, // CONTINUAR en crear-personaje (nick + atributos)
    SELECCIONAR       = 0x139f, // auto-selección / ENTRAR con un índice de personaje
    LATIDO            = 0x13a1, // "heartbeat", lo envía cada ~5 segundos
    PIDE_SERVIDORES   = 0x13aa, // GETAVAILABLESERVERS: pide la lista de cárceles
    JUGAR             = 0x13f1, // pulsó JUGAR (pide entrar al mundo)
};

// ===========================================================================
//  2) SERVIDOR  ->  CLIENTE   (lo que respondemos en el LOGIN)
// ===========================================================================
enum OpcodeServidor : uint16_t {
    CUENTA               = 0x1389, // estructura de la cuenta + personajes (fragmentada)
    LOGINRECHAZADO       = 0x138a, // LOGINREJECTED: rechaza el login, payload [codigo:1] (+timestamp si codigo=7)
    CHARCREATED          = 0x1395, // confirma que el personaje se creó
    CHARERROR            = 0x1398, // error al crear (p.ej. "El nick ya existe, elige otro")
    SERVERADDED          = 0x13a9, // añade una "prisión" (servidor) a la lista, con su nombre
    AVAILABLESERVERS     = 0x13ac, // lista de servidores disponibles (nº de "reclusos")
    CLASSINFO            = 0x13c2, // tabla de clases (para la pantalla de selección)
    LOGINACCEPTED        = 0x13d5, // login aceptado (count=0); también lista RICA (count>0)
    ENTERINGGAMEACCEPTED = 0x13f2, // permiso concedido para entrar al juego (respuesta a JUGAR)
};

// ===========================================================================
//  3) MUNDO (juego) — opcodes PEQUEÑOS de control
//     Son números bajos (0..9) que van al PRINCIPIO del payload.
// ===========================================================================
enum OpcodeMundoControl : uint16_t {
    ROOMPARAMS    = 0, // configura la sala (mapa, id de sala, plantilla)
    CREAR_JUGADOR = 2, // crea al jugador local (nombre, id, posición)
    ENTRAR        = 3, // actualiza al jugador y lo hace ENTRAR (puerta = 0xff)
    ROOMREADY     = 6, // la sala está lista; da el control al jugador
    PING          = 9, // PING del cliente (le respondemos con el mismo = PONG)
};

// ===========================================================================
//  4) MUNDO (juego) — opcodes GRANDES (0x13xx)
// ===========================================================================
enum OpcodeMundo : uint16_t {
    PASSDOOR    = 0x138e, // (cliente->servidor) el cliente cruza la puerta de entrada
    SERVERPARAMS = 0x139e, // parámetros de sesión + temporizadores de ping
    // Tablas de datos de sala (todas: [opcode:2][uncompSize:4][compSize:4][zlib]).
    // El cliente las despacha restando 0x1388 al opcode (handler 0x4b4839):
    //   0x13a4-0x1388=0x1c BOXESINFO, 0x13a5=0x1d MAPINFO, 0x13a6=0x1e SUPPLIESINFO,
    //   0x13a7=0x1f BOTSINFO(NPCInfo), 0x13a8=0x20 OBJECTSINFO, 0x14ee=0x166 QUESTSINFO.
    BOXESINFO   = 0x13a4, // tabla de cajas
    MAPINFO     = 0x13a5, // definición de mapas/plantillas
    SUPPLIESINFO= 0x13a6, // tabla de "supplies" (vendedores/loot)  -> parser 0x4a0000
    BOTSINFO    = 0x13a7, // tabla de NPCs/bots (NPCInfo)            -> parser 0x4a03c0
    OBJECTINFO  = 0x13a8, // tabla de objetos/items                  -> parser tipo objtable
    QUESTSINFO  = 0x14ee, // tabla de misiones
};

// ===========================================================================
//  5) REFERENCIA — opcodes documentados de la ingeniería inversa
//     (no todos se usan todavía, pero conviene tenerlos nombrados)
// ===========================================================================
enum OpcodeReferencia : uint16_t {
    // --- net del servidor -> cliente ---
    REF_CHARERROR        = 0x1397, // error al crear/borrar personaje  (-> evento 0x486)
    REF_CLASSINFO_NET    = 0x13c1, // CLASSINFO (etiqueta del manejador; se ENVÍA 0x13c2)
    REF_KICKED           = 0x13c0, // expulsado del servidor            (-> evento 0x48d)
    REF_AVAILSERVERS_NET = 0x13d4, // AVAILABLESERVERS con contador (path de actualizaciones)
    REF_ENTERINGGAME_NET = 0x13f1, // ENTERINGGAMEACCEPTED (etiqueta; se ENVÍA 0x13f2)
    REF_ENTERINGDENIED   = 0x13f2, // ENTERINGGAMEDENIED (etiqueta; se ENVÍA 0x13f3...)

    // --- eventos LOCALES del cliente (NO van por la red; solo de referencia) ---
    EVT_CONNECTED            = 0x47f,
    EVT_DISCONNECTED         = 0x480,
    EVT_CONNECTIONFAILED     = 0x481,
    EVT_LOGINACCEPTED        = 0x482,
    EVT_LOGINREJECTED        = 0x483,
    EVT_CHARCREATED          = 0x484,
    EVT_CHARDELETED          = 0x485,
    EVT_CHARERROR            = 0x486,
    EVT_ENTEREDINROOM        = 0x487,
    EVT_SERVERADDED          = 0x489,
    EVT_AVAILABLESERVERS     = 0x48b,
    EVT_KICKED               = 0x48d,
    EVT_SERVERLOCKED         = 0x48f,
    EVT_ENTERINGGAMEACCEPTED = 0x4af,
    EVT_ENTERINGGAMEDENIED   = 0x4b0,
};

} // namespace op
} // namespace prison
