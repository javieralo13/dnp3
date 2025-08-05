/*
 * dnp3.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef T2_DNP3_H_INCLUDED
#define T2_DNP3_H_INCLUDED

// Global includes

//#include <string.h>

// Local includes

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */
#define DNP_DEBUG      0 // Print debug messages


/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define DNP3_FNAME  "filename.txt" // File to load from the plugin folder (require DNP3_LOAD=1)
#define DNP3_SUFFIX "_suffix.txt"  // Suffix for output file (require DNP3_STATS=1)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */

// Estados para la máquina de reensamblado de cabeceras DNP3.
typedef enum {
    DNP3_HDR_STATE_NONE = 0,      // Estado inicial, esperando un nuevo mensaje.
    DNP3_HDR_STATE_WANT_LINK_HDR, // Esperando el resto de una cabecera de enlace (10 bytes) fragmentada.
    DNP3_STATE_WANT_BODY,           // Tenemos una cabecera válida, estamos esperando el resto del cuerpo del mensaje.
    // hasta 254
} DNP3_HdrState;
// plugin defines
// tcpWinStat status variable
// Status
#define DNP_STAT_DNP3            0x0001 // 1 - flow is dnp3
#define DNP_STAT_000             0x0002 // VACIO, Libre
#define DNP_STAT_001             0x0004 // VACIO, Libre
#define DNP_STAT_002             0x0008 // VACIO, Libre
#define DNP_STAT_DU_SNAP         0x0010 // data link snap data user
#define DNP_STAT_1               0x0020 // VACIO, Libre
#define DNP_STAT_2               0x0040 // VACIO, Libre
#define DNP_STAT_DL              0x0080 // 8 - DNP3 Valid Header 0x0564
#define DNP_STAT_6               0x0100 // VACIO, Libre
#define DNP_STAT_7               0x0200 // VACIO, Libre
#define DNP_STAT_MALFORMED_L     0x0400 // malformed packet  LEN datalink
#define DNP_STAT_MALFORMED_R     0x0800 // malformed packet in SNAP Data Link packet
#define DNP_STAT_REASSEMBLY_FAIL 0x1000 // Falla en el reensamblado (p.ej. paquete perdido)
#define DNP_STAT_4               0x2000 // VACIO, Libre
#define DNP_STAT_5               0x4000 // VACIO, Libre
#define DNP_STAT_MALFORMED       0x8000 // 16 - malformed packet

#define DNP3_PORT  20000    // Common port of DNP3

//plugin defines - DNP3 protocol
#define DNP3_STREAM_BUFFER_SIZE 2048 // 2KB por dirección, ajustable
// #define DNP3_START 0x0564     // frame init bytes,data Link Layer, use uint16_t in variables;
// #define dataLink_len 0x0A     // length bytes example if( len(*streamBytes) = dataLink_len )
// #define appHeader_len 0x04     // length bytes example if( len(*streamBytes) = appHeader_len )
// ...
#if DNP_DEBUG == 1
#define DNP_DBG(format, args...) T2_PINF(plugin_name, format, ##args)
#else // DNP_DEBUG == 0
#define DNP_DBG(format, args...) /* do nothing */
#endif // DNP_DEBUG == 0


// Plugin structure
// --- Empaquetado de 1 byte para todas las estructuras de protocolo ---
#pragma pack(push, 1)

/**
 * @brief Cabecera de la Capa de Enlace DNP3 (10 bytes). Fija.
 */
typedef struct {
    uint16_t start;       // 0x0564
    uint8_t  len;         // Longitud del frame
    uint8_t  ctrl;        // Campo de control de enlace
    uint16_t destination; // Dirección de destino
    uint16_t source;      // Dirección de origen
    uint16_t crc;         // CRC de la cabecera
} dnp3_LinkLayerHeader;

/**
 * @brief Byte de control de la Capa de Transporte DNP3 (1 byte). Fijo.
 * Lo definimos como un tipo para mayor claridad en el código.
 * Contiene los bits FIR (First) y FIN (Final) y una secuencia de 6 bits.
 */
typedef uint8_t DNP3_TransportControl;

/**
 * @brief Cabecera de la Capa de Aplicación DNP3 (4 bytes). Fija.
 * Esta cabecera precede a los objetos de datos variables.
 */
typedef struct {
    uint8_t  app_control;   // Application Control (FIR, FIN, CON, UNS, SEQ)
    uint8_t  function_code; // Function Code (READ, WRITE, OPERATE, etc.)
    uint16_t iin;           // Internal Indications (solo en respuestas)
} DNP3_AppHeader;

/**
 * @brief Cabecera de Objeto DNP3 (mínimo 3 bytes). ¡La clave para datos variables!
 * Esta es la cabecera que precede a CADA objeto o grupo de objetos en el payload.
 */
typedef struct {
    uint8_t group;     // Grupo del objeto (e.g., 1=Entrada Binaria, 30=Entrada Analógica)
    uint8_t variation; // Variación específica (e.g., 1=estado, 2=estado con bandera)
    uint8_t qualifier; // Código calificador (cómo interpretar el rango)
    // --- NOTA: El rango o los datos del objeto vienen DESPUÉS de esta cabecera ---
} DNP3_ObjectHeader;


#pragma pack(pop)


// --- Estructura de "gestión" para uso interno en tu disector ---
// NO se mapea directamente a la red. Es para guardar los resultados del parseo.

/**
 * @brief Contenedor para un mensaje DNP3 completamente parseado.
 * Esta estructura no se mapea a los bytes de la red, sino que se usa para
 * pasar la información ya decodificada a la lógica de detección de anomalías.
 */
typedef struct {
    const dnp3_LinkLayerHeader* link_header;    // Puntero al inicio del paquete
    DNP3_AppHeader              app_header;     // Copia de la cabecera de aplicación
    const uint8_t* objects_payload;             // Puntero al inicio de los objetos
    int                         objects_len;    // Longitud del payload de objetos
    // Aquí puedes añadir más metadatos, como el timestamp del paquete, etc.
} ParsedDNP3Message;

/**
 * @brief Estructura para un buffer dinámico que almacena el stream TCP reensamblado.
 */
typedef struct {
    uint8_t *buffer;    // Puntero a la memoria asignada dinámicamente.
    uint32_t len;       // Bytes actualmente usados en el buffer.
    uint32_t lastlen;       // podrias usarse para comparar el paquete duplicado con mas bytes.
    uint32_t allocated; // Total de bytes asignados en memoria.
} dnp3_stream_buffer_t;

/**
 * @brief Almacena metadatos de seguridad y estado para un único flujo DNP3.
 *
 * Esta estructura acumula información clave de la capa de aplicación a lo largo
 * de toda la vida de una sesión TCP para facilitar la detección de anomalías.
 */
typedef struct {
    /**
     * @brief Bitmap de todos los códigos de función DNP3 vistos en este flujo.
     * Esencial para la seguridad. Permite detectar con una simple operación de bits
     * si se han usado funciones peligrosas (WRITE, OPERATE, RESTART, etc.).
     * Ejemplo: Si se ve un READ (FC=1), se activa el bit 1. Si se ve un WRITE (FC=2), el bit 2.
     */
    uint32_t function_codes_seen;

    /**
     * @brief Bitmap de los grupos de objetos críticos accedidos en el flujo.
     * Permite saber si el flujo ha intentado leer o escribir en objetos sensibles
     * como relés de control (Grupo 12), configuración, etc., sin tener que
     * almacenar cada objeto individualmente.
     */
    uint16_t critical_objects_seen;  // 0x00: Grupo 12 Control Relay Output Block (CROB)
                                    // 0x01: Grupo 41 - Analog Output Block (AOB)
                                    // 0x02: Grupo 70 - File Control
                                    // 0x03: Grupo 60 - Class Assignment
                                    // 0x04: Grupo 50 - Time and Date
                                    // 0x05: Grupo 80 - Internal Indications (IIN)
                                    // 0x06: Grupo 20 - Counter
                                    // 0x07: Grupo 110/111 - Device Profile / Private Objects 
                                    // 0x08: Grupo 40 - Analog Output Status
                                    // 0x09: Grupo 120 - Authentication (DNP3-SA)
    /**
     * @brief Dirección DNP3 del dispositivo maestro en este flujo.
     */
    uint16_t master_addr;

    /**
     * @brief Dirección DNP3 del dispositivo outstation (esclavo) en este flujo.
     */
    uint16_t outstation_addr;

    /**
     * @brief Bitmap acumulativo de todas las banderas de Indicaciones Internas (IIN)
     * vistas en las respuestas del outstation.
     * Esencial para detectar reinicios del dispositivo (IIN1.0), corrupción de
     * configuración (IIN1.4), desbordamiento de buffer (IIN2.1), etc.
     */
    uint16_t iin_flags_seen;

    /**
     * @brief Almacena el último número de secuencia de aplicación visto del maestro al outstation.
     * Clave para detectar paquetes reinyectados (replay) o perdidos en esta dirección.
     */
    uint8_t last_master_seq;

    /**
     * @brief Almacena el último número de secuencia de aplicación visto del outstation al maestro.
     * Clave para detectar paquetes reinyectados o perdidos en esta dirección.
     */
    uint8_t last_outstation_seq;

    /**
     * @brief Bandera que se activa si se ha visto al menos una solicitud con el bit CON (confirmación).
     */
    uint8_t confirm_requested;

    /**
     * @brief Bandera que se activa si se ha visto al menos una respuesta no solicitada (UNS).
     * Un pico de respuestas no solicitadas puede indicar un problema o un ataque.
     */
    uint8_t unsolicited_seen;
    
    // member to tracking dnp3 status 
    uint16_t  stat;             // status
    
    // --- MIEMBROS PARA EL REENSAMBLADO TCP ---
    /**
     * @brief Estado actual de la máquina de reensamblado para este flujo.
     * Usa los valores del enum DNP3_HdrState.
     */
    uint8_t  hdr_stat;

    /**
     * @brief Contador de cuántos bytes de una cabecera fragmentada ya hemos recibido.
     */
    uint16_t  hdroff;

    /**
     * @brief Buffer temporal para almacenar los bytes de una cabecera DNP3 fragmentada.
     * El tamaño 10 es para la cabecera de la capa de enlace, que es lo primero
     * que debemos asegurar que tenemos completo.
     */
    uint8_t  hdr_buf[10];

    /**
     * @brief Almacena el número de secuencia TCP del próximo byte que esperamos recibir.
     * Esencial para detectar si se han perdido segmentos TCP en medio de un mensaje.
     */
    uint32_t tcp_seq;

/**
 * @brief Estructura principal del flujo DNP3, con buffers dinámicos para cada dirección.
 */
    dnp3_stream_buffer_t client_stream; // Buffer para datos del cliente -> servidor.
    dnp3_stream_buffer_t server_stream; // Buffer para datos del servidor -> cliente.


    uint32_t tcp_seq_client; // Próximo SEQ esperado del cliente.
    uint32_t tcp_seq_server; // Próximo SEQ esperado del servidor.
    
    // banderas DEBUG - BORRAR 
    // Contador de cuántos bytes faltan para completar el frame DNP3 actual (incluyendo cabecera, cuerpo y todos los CRCs).
    uint32_t frame_bytes_remaining; 
    uint32_t u32flag1; // conteo paquetes malformados en TCP / dnp3Flowp->seq!=packet->seq
    uint8_t u8flag2; // conteo paquetes malformados tcp
    uint32_t u32flag3; // conteo paquetes malformados en dnp3 Data link
    
    uint8_t  dhr_buf_save[10];
} dnp3Flow_t;




// plugin struct pointer for potential dependencies
extern dnp3Flow_t *dnp3Flows;

#endif // T2_DNP3_H_INCLUDED