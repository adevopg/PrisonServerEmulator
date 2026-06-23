// ============================================================================
//  protocolo_sns.hpp  —  Definición del protocolo de red "SNS"
// ============================================================================
//
//  ¿QUÉ ES EL PROTOCOLO SNS?
//
//  Es el protocolo de transporte "UDP fiable" que usa "Carcelclient.exe"
//  (el juego "La Prisión"). Cada paquete empieza con una CABECERA de 22 bytes
//  (0x16 en hexadecimal) y, detrás, va el "payload" (los datos de aplicación).
//
//  CABECERA SNS (22 bytes):
//
//    Offset  Tamaño  Nombre          Significado
//    ------  ------  --------------  ---------------------------------------------
//    0x00    u32     connID_lo       0xFFFFFFFF durante el handshake; 1 en datos
//    0x04    u32     connID_hi       = id de conexión asignado (en fase de datos)
//    0x08    u16     flags           bit0=pide-ACK, bit1=es-ACK, bit2=lleva-datos
//    0x0a    u8      ventana         (window) distinto de 0
//    0x0b    u8      ack             (ack) menor que la ventana
//    0x0c    u32     campoC          id de mensaje (el ACK lo repite para emparejar)
//    0x10    u32     marcaTiempo     timestamp
//    0x14    u16     secuencia       seq
//    0x16    ...     payload         datos (cifrados en fase de datos; en claro en handshake)
//
//  HANDSHAKE (saludo inicial):
//    1) cliente -> SYN     (tipo 3, lleva el nombre de usuario)
//    2) servidor -> SYN-ACK(tipo 6, asigna connID + material de clave)
//    3) cliente -> ACK     (tipo 7) -> conexión ESTABLECIDA
//
//  INTERCAMBIO DE CLAVE (en el SYN-ACK):
//    Con la clave K y un timestamp TS, el servidor codifica:
//        f1 = ((TS ^ K) & MASCARA) ^ K     (va en offset 0x10)
//        f2 = ((TS ^ K) & MASCARA) ^ TS    (va en offset 0x0c)
//    El cliente recupera K con:  K = ((f1 ^ f2) & MASCARA) ^ f1
// ============================================================================
#pragma once

#include <cstdint>

namespace prison {
namespace protocolo {

// ---- Tamaños y offsets de la cabecera SNS ----
constexpr int TAM_CABECERA       = 0x16; // 22 bytes
constexpr int OFF_CONN_LO        = 0x00;
constexpr int OFF_CONN_HI        = 0x04;
constexpr int OFF_FLAGS          = 0x08;
constexpr int OFF_VENTANA        = 0x0a;
constexpr int OFF_ACK            = 0x0b;
constexpr int OFF_CAMPO_C        = 0x0c;
constexpr int OFF_MARCA_TIEMPO   = 0x10;
constexpr int OFF_SECUENCIA      = 0x14;
constexpr int OFF_PAYLOAD        = 0x16; // aquí empiezan los datos
constexpr int OFF_TIPO           = 0x16; // u16: tipo de paquete (handshake)
constexpr int OFF_CONST          = 0x18; // u16: constante = 4
constexpr int OFF_NONCE          = 0x1a; // u32: nonce
constexpr int OFF_DATOS          = 0x1e; // datos tras el nonce (ej: usuario en el SYN)

// ---- Banderas (flags, offset 0x08) ----
constexpr uint16_t FLAG_PIDE_ACK   = 1; // bit0: el emisor pide que confirmemos
constexpr uint16_t FLAG_ES_ACK     = 2; // bit1: este paquete ES una confirmación
constexpr uint16_t FLAG_LLEVA_DATOS = 4; // bit2: lleva datos de aplicación

// ---- Tipos de paquete en el handshake (offset 0x16) ----
constexpr uint16_t TIPO_SYN     = 3; // cliente -> servidor (inicia conexión)
constexpr uint16_t TIPO_SYN_ACK = 6; // servidor -> cliente (acepta, da id + clave)
constexpr uint16_t TIPO_ACK     = 7; // cliente -> servidor (confirma, establecida)

// ---- Máscara del intercambio de clave (sacada del cliente) ----
constexpr uint32_t MASCARA_CLAVE = 0x7e34fc22u;

// ---- Marcador de "es un paquete de handshake" ----
constexpr uint32_t CONN_HANDSHAKE = 0xFFFFFFFFu; // connID_lo durante el handshake

// ---- Puertos UDP del servidor ----
constexpr uint16_t PUERTO_LOGIN   = 25666; // servidor de login
constexpr uint16_t PUERTO_UPDATES = 25667; // servidor de actualizaciones
constexpr uint16_t PUERTO_MUNDO   = 25001; // servidor de mundo (juego)

// ----------------------------------------------------------------------------
//  componerMensajeApp: prepara el payload "fiable" que espera el cliente.
//
//  El cliente valida que los datos entregados sean una cadena de registros con
//  prefijo de longitud terminada en un registro de longitud 0:
//        M = [longRegistro:4][registro][0:4]
//        registro = [idConexion:4][1:4][datosApp]
//        payload  = [idConexion:4][1:4] + M
//
//  Parámetros:
//    salida     = buffer donde se escribe el payload completo
//    idConexion = id de esta conexión
//    datosApp   = los datos de aplicación (ej: [opcode:2][...])
//    n          = longitud de datosApp
//  Devuelve la longitud total escrita en "salida".
// ----------------------------------------------------------------------------
int componerMensajeApp(uint8_t* salida, uint32_t idConexion,
                       const uint8_t* datosApp, int n);

} // namespace protocolo
} // namespace prison
