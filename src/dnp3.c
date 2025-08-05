/*
 * dnp3.c
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

#include "dnp3.h"

//#include "t2buf.h"


/*
 * Plugin variables that may be used by other plugins MUST be declared in
 * the header file as 'extern dnp3Flow_t *dnp3Flows;'
 */

dnp3Flow_t *dnp3Flows;


/*
 * Static variables are only visible in this file
 */

//static uint32_t numMalfPkts;


/*
 * Static functions prototypes
 */

// static inline void dnp3_extractHash(FILE *stream);


// Tranalyzer functions

/*
 * This describes the plugin name, version, major and minor version of
 * Tranalyzer required and dependencies
 */
T2_PLUGIN_INIT("dnp3", "0.9.3", 0, 9);
//T2_PLUGIN_INIT_WITH_DEPS("dnp3", "0.9.3", 0, 9, "tcpFlags,tcpStates");

/*
 * This function is called before processing any packet.
 */
 void t2Init() {
    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(dnp3Flows);
}


/*
 * This function is used to describe the columns output by the plugin
 */
binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv, "dnp3Stat" , "DNP3 status");
    BV_APPEND_H32(bv , "u32flag1"  , "u32flag1"); 
    //BV_APPEND_H32(bv , "u32flag3"  , "u32flag3"); 
    //BV_APPEND_H8_R( bv, "dhr_buf_save"     , "data link header ");
    return bv;
}


/*
 * This function is called every time a new flow is created.
 */
void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    // Reset the structure for this flow
    dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];
    memset(dnp3FlowP, '\0', sizeof(*dnp3FlowP));
    
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    // process only TCP and DNP3 port TODO: VALID_DNP3_PORT(srcPort, dstPort)
    if (flowP->l4Proto == L3_TCP && (flowP->srcPort == DNP3_PORT || flowP->dstPort == DNP3_PORT))
        dnp3FlowP->stat |= DNP_STAT_DNP3;
}


/* ========================================================================== */
/* -------------------------- FUNCIONES DE AYUDA ---------------------------- */
/* ========================================================================== */

static bool dnp3_stream_append(dnp_strm_bf_t *streamBuffP, const uint8_t *payload, const uint16_t payload_len) {
    if (streamBuffP->allocated == 0) {
        const size_t initial_size = 292;
        streamBuffP->buffer = t2_malloc(initial_size);
        if (!streamBuffP->buffer) {
            return false;
        }
        streamBuffP->allocated = initial_size;
    }

    const size_t new_len = streamBuffP->len + payload_len;
    if (new_len > streamBuffP->allocated && streamBuffP->allocated>1 ) { //safety_lock
        // safety_lock para que new_alloc_size aumente si o si no se quede trabado en while
        // TODO: UNLIKELY (0.26% tcp.len>292)(other 47.8% is less than 292 bytes)
        size_t new_alloc_size = streamBuffP->allocated;
        while (new_len > new_alloc_size) { new_alloc_size *= 2; } //ejemplo new_len=584(292*2)

        uint8_t *tmp = t2_realloc(streamBuffP->buffer, new_alloc_size);
        if (!tmp) {
            T2_PERR(plugin_name, "Fallo al reasignar memoria para buffer DNP3");
            t2_free(streamBuffP->buffer);
            streamBuffP->buffer = NULL;
            streamBuffP->allocated = 0;
            streamBuffP->len = 0;
            return false;
        }
        streamBuffP->buffer = tmp;
        streamBuffP->allocated = new_alloc_size;
    }
    memcpy(&streamBuffP->buffer[streamBuffP->len], payload, payload_len);
    streamBuffP->len = new_len;
    return true;
}


static void parse_dnp3_stream(dnp_strm_bf_t *stream, dnp3Flow_t *flow_state) {
    int safety_lock = 0;
    const int max_loops = 100; // Un número alto de frames DNP3 concatenados en un solo buffer es improbable.
                                // 1500 por MTU y 292 max frame dnp3  1500/292 aprox 5.13
    
    while (safety_lock++ < max_loops) { 
        if (stream->len < sizeof(dnp3_LinkLayerHeader)) {
            break; // No hay suficientes datos para una cabecera, esperamos más.
        }

        // Usamos el buffer reensamblado como fuente de datos
        const uint8_t *frame_buff = stream->buffer;

        // Comprobación de cabecera (byte por byte, como acordamos)
        if (frame_buff[0] != 0x05 || frame_buff[1] != 0x64) {
            flow_state->stat |= DNP_STAT_MALFORMED;
            DNP_DBG("Error de sincronización DNP3, vaciando buffer.");
            stream->len = 0; // Descartamos datos inválidos.
            break;
        }

        const dnp3_LinkLayerHeader *hdr = (const dnp3_LinkLayerHeader *)frame_buff;
        const uint8_t len_field = hdr->len;

        if (len_field < 5) {
            flow_state->stat |= DNP_STAT_MALFORMED;
            DNP_DBG("Campo LENGTH inválido (%u), vaciando buffer.", len_field);
            stream->len = 0;
            break;
        }
        
        // Calculamos el tamaño total del frame DNP3
        const uint8_t user_data_len = len_field - 5;
        const uint32_t num_user_data_crcs = ((uint32_t)user_data_len + 15) / 16;
        const uint32_t total_frame_size = 10 + user_data_len + (num_user_data_crcs * 2);

        // ¿Tenemos el frame completo en nuestro buffer?
        if (stream->len < total_frame_size) {
            DNP_DBG("Frame DNP3 incompleto en buffer. Esperando %u más.", total_frame_size - stream->len);
            break; // No, salimos y esperamos más datos.
        }

        // --- ¡ÉXITO! TENEMOS UN FRAME DNP3 COMPLETO EN EL BUFFER ---
        flow_state->stat |= DNP_STAT_DL;
        DNP_DBG("¡Frame DNP3 completo de %u bytes parseado desde el stream!", total_frame_size);
        
        // AQUÍ: Se haría el análisis profundo de los datos de usuario (capa de transporte/aplicación)
        // usando los primeros 'total_frame_size' bytes de 'stream->buffer'.

        // "Consumimos" el frame del buffer, moviendo los datos restantes al principio.
        // TODO: podriamos necesitar para los paquetes duplicados siguientes
        stream->len -= total_frame_size;
        if (stream->len > 0) {
            memmove(stream->buffer, &stream->buffer[total_frame_size], stream->len);
        }
    }
    
    if (safety_lock >= max_loops) { 
        DNP_DBG("¡ADVERTENCIA! El candado de seguridad se activó en parse_dnp3_stream. Posible bucle infinito evitado.");
        // Se podría añadir una bandera de estado para reportar este evento.
        stream->len = 0; // Vaciamos el buffer para estar seguros.
    }    
}


/*
 * This function is called for every packet with a layer 4.
 */
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    // 1. --- CONFIGURACIÓN INICIAL Y GUARDAS ---
    dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];
    dnp_strm_bf_t * const streamBuffP = &dnp3FlowP->stream_dnp3;
    
    if (!(dnp3FlowP->stat & DNP_STAT_DNP3)) {
        // not a dnp3 packet
        DNP_DBG("Non-DNP3 Protocol Identifier in flow %" PRIu64, flows[flowIndex].findex);
        return;
    }

    const uint32_t tcpSeq = ntohl(TCP_HEADER(packet)->seq);
    const uint16_t payloadLen = packet->snapL7Len;
    const uint8_t *payload = packet->l7HdrP;
      
    if (payloadLen == 0) return; // Si el paquete no tiene payload (p.ej. un simple TCP ACK), no hay nada que parsear.
    
    //if (!t2_is_first_fragment(packet)) return; 

    // 2. --- DETECCIÓN DE SEGMENTOS TCP PERDIDOS ---
    if (dnp3FlowP->expected_seq != 0) { // Solo comprobamos si ya hemos visto un paquete antes
        if (tcpSeq < dnp3FlowP->expected_seq) {
            // CASO 1: PAQUETE DUPLICADO/RETRANSMITIDO
            DNP_DBG("Paquete TCP duplicado detectado. Ignorando.");
            //dnp3FlowP->stat |= DNP_STAT_DUPLICATE_TCP;
            /*
             * TODO: Ignoramos pero esta el caso que que la master envie nuevamente el mismo   
             * paquete duplicado pero con otro frame como en tcp.seq_raw == 0x092b1213
             */
            return; // Ignoramos el paquete, no actualizamos nada.
        }
        if (tcpSeq > dnp3FlowP->expected_seq) {
            // CASO 2: PAQUETE PERDIDO (SECUENCIA SALTÓ)
            DNP_DBG("ERROR: Paquete perdido. Esperado: %u, Recibido: %u", dnp3FlowP->expected_seq, tcpSeq);
            dnp3FlowP->stat |= DNP_STAT_REASSEMBLY_FAIL;
            // Podríamos resetear el buffer aquí si quisiéramos ser más estrictos
            // streamBuffP->len = 0;
            // No retornamos aún, procesamos este paquete como el inicio de un nuevo intento.
            dnp3FlowP->u32flag1++; // nos sirve para indagar que IPs con mas problables a DNP_STAT_REASSEMBLY_FAIL            
            /*
             * if (!dnp3FlowP->u8flag2) { // Si no se ha guardado una antes
                dnp3FlowP->u8flag2 = 1; // Marca que ya se guardó
                dnp3FlowP->u32flag1= tcpSeq;
            }
            */            
        }
    }
 
    // 3. Añadir datos al buffer dinámico
    if (!dnp3_stream_append(streamBuffP, payload, payloadLen)) {
        DNP_DBG("ERROR: No se puede asignar memoria para los %u bytes", payloadLen );
        return; 
    }
    
    // 4. Intentar parsear el stream con los nuevos datos
    parse_dnp3_stream(streamBuffP, dnp3FlowP);

    // 5. Actualizar la secuencia esperada
    dnp3FlowP->expected_seq = tcpSeq + payloadLen;

}

/*
 * This function is called once a flow is terminated.
 * Output all the statistics for the flow here.
 */
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];

    OUTBUF_APPEND_U16(buf, dnp3FlowP->stat); // dnp3Stat
    OUTBUF_APPEND_U32(buf , dnp3FlowP->u32flag1);  // 
    //OUTBUF_APPEND_U32(buf , dnp3FlowP->u32flag3);   //  
    //OUTBUF_APPEND_ARRAY_U8(buf , dnp3FlowP->dhr_buf_save, 10); // 
    
    // --- LIBERACIÓN DE MEMORIA CRUCIAL ---
    t2_free(dnp3FlowP->stream_dnp3.buffer);
}

/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here.
 */
void t2Finalize() {
    free(dnp3Flows);
}
