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

// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_DNP3_FNAME,
    ENV_DNP3_N,
};
// plugin defines
// tcpWinStat status variable
// Status
#define DNP_STAT_DNP3      0x0001 // flow is dnp3
#define DNP_STAT_PROTO     0x0002 // non-modbus protocol identifier
#define DNP_STAT_FUNC      0x0004 // unknown function code
#define DNP_STAT_EX        0x0008 // unknown exception code
#define DNP_STAT_UID       0x0010 // multiple unit identifiers
#define DNP_STAT_1         0x0020 //
#define DNP_STAT_2         0x0040 //
#define DNP_STAT_DL        0x0080 // DNP3 Valid Header 0x0564
#define DNP_STAT_NFUNC     0x0100 // list of function codes truncated... increase MB_NUM_FUNC
#define DNP_STAT_NFEX      0x0200 // list of function codes which caused exceptions truncated... increase MB_NUM_FEX
#define DNP_STAT_NEXCP     0x0400 // list of exception codes truncated... increase MB_NUM_EX
#define DNP_STAT_SNAP      0x4000 // snapped packet
#define DNP_STAT_MALFORMED 0x8000 // malformed packet

#define DNP3_PROTO 0x0000
#define DNP3_PORT  20000    // TCP
// plugin defines - DNP3 protocol
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
} DNP3_LinkLayerHeader;

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
    const DNP3_LinkLayerHeader* link_header;    // Puntero al inicio del paquete
    DNP3_AppHeader              app_header;     // Copia de la cabecera de aplicación
    const uint8_t* objects_payload;             // Puntero al inicio de los objetos
    int                         objects_len;    // Longitud del payload de objetos
    // Aquí puedes añadir más metadatos, como el timestamp del paquete, etc.
} ParsedDNP3Message;

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
    uint8_t critical_objects_seen;  // 0x00: Grupo 12 Control Relay Output Block (CROB)
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
} dnp3Flow_t;




// plugin struct pointer for potential dependencies
extern dnp3Flow_t *dnp3Flows;

#endif // T2_DNP3_H_INCLUDED
