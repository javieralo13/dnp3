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
    BV_APPEND_U16(bv, "dnp3cntFrm", "Count dnp3 frames");
    BV_APPEND_U32(bv , "restFrames"  , "u32flag2"); 
    BV_APPEND_U32(bv , "syncHDrFail"  , "u32flag7");
    BV_APPEND_U32(bv , "tcpcntReassFl"  , "u32flag8");
    BV_APPEND_FLT(bv, "dnp3avgFrameSz" , "Average Frame Size");
    //BV_APPEND_H32_R(bv, "lst_expc_seq"     , "dnp3 last tcp seq tracking");
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
    // TODO-1: PROBAR REMOVER
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    // process only TCP and DNP3 port TODO: VALID_DNP3_PORT(srcPort, dstPort)
    if (flowP->l4Proto == L3_TCP && (flowP->srcPort == DNP3_PORT || flowP->dstPort == DNP3_PORT))
        dnp3FlowP->stat |= DNP_STAT_DNP3;
}


/* ========================================================================== */
/* -------------------------- FUNCIONES DE AYUDA ---------------------------- */
/* ========================================================================== */

static inline bool dnp3_stream_append(dnp_stream_t *streamBuffP, const uint8_t *payload, const uint16_t payload_len) {
    // new allocate size of buffer, default 292 max dnp3 fragment in datalink layer
    if (streamBuffP->allocated == 0) {
        const size_t initial_size = 292;
        streamBuffP->buffer = t2_malloc(initial_size);
        if (!streamBuffP->buffer) return false;
        streamBuffP->allocated = initial_size;
    }

    const size_t new_len = streamBuffP->len + payload_len;
    if (UNLIKELY( new_len > streamBuffP->allocated && streamBuffP->allocated>1) ) { //safety_lock allocated>1
        // (0.26% tcp.len>292 other 47.8% is less than 292 bytes)
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
    streamBuffP->len = (uint16_t)new_len;
    return true;
}


static inline void parse_dnp3_stream(dnp_stream_t *stream, dnp3Flow_t *flow_stat) {
    int safety_lock = 0;
    const int max_loops = 100; // 1500 por MTU y 292 max frame dnp3  1500/292 aprox 5.13
    
    while (safety_lock++ < max_loops) { 
        if (stream->len < sizeof(dnp3_LinkLayerHeader)) {
            break; // No hay suficientes datos para una cabecera, esperamos más.
        }

        // Usamos el buffer reensamblado como fuente de datos
        const uint8_t *frame_buff = stream->buffer;

        // Comprobación de cabecera 
        if (frame_buff[0] != 0x05 || frame_buff[1] != 0x64) {
            flow_stat->stat |= DNP_STAT_MALFORMED;
            flow_stat->u32flag7++;
            DNP_DBG("Error de sincronización DNP3, vaciando buffer.");
            stream->len = 0; // Descartamos datos inválidos.
            break;
        }
        
        const dnp3_LinkLayerHeader *hdr = (const dnp3_LinkLayerHeader *)frame_buff;
        const uint8_t len_field = hdr->len;

        if (len_field < 5) {
            flow_stat->stat |= DNP_STAT_MALFORMED;
            DNP_DBG("Campo LENGTH inválido (%u), vaciando buffer.", len_field);
            stream->len = 0;
            break;
        }
        
        // Calculamos el tamaño total del frame 
        const uint8_t user_data_len = len_field - 5; //5 bytes fijos de un frame dnp3
        const uint16_t num_user_data_crcs = ((uint16_t)user_data_len + 15) / 16;
        const uint16_t total_frame_size = 10 + user_data_len + (num_user_data_crcs * 2);

        // ¿Tenemos el frame completo en nuestro buffer?
        if (stream->len < total_frame_size) {
            DNP_DBG("Frame DNP3 incompleto en buffer. Esperando %u más.", total_frame_size - stream->len);
            break; // No, salimos y esperamos más datos.
        }

        // --- ¡ÉXITO! TENEMOS UN FRAME DNP3 COMPLETO EN EL BUFFER ---
        flow_stat->stat |= DNP_STAT_DL;
        DNP_DBG("¡Frame DNP3 completo de %u bytes parseado desde el stream!", total_frame_size);
        
        // AQUÍ: Se haría el análisis profundo de los datos de usuario (capa de transporte/aplicación)
        // usando los primeros 'total_frame_size' bytes de 'stream->buffer'.
        flow_stat->u32flag1 += (uint32_t)total_frame_size; 
        flow_stat->cntFrm++; // conteo de: dnp3.al.func == 0x81 || dnp3.al.func == 0x01 PARA dnp3.al.'len'< 288
        // "Consumimos" el frame del buffer, moviendo los datos restantes al principio.
        stream->len -= total_frame_size;
        if (stream->len > 0) {
            memmove(stream->buffer, &stream->buffer[total_frame_size], stream->len);
            flow_stat->u32flag2++;
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
    // 1. --- CONFIGURACION INICIAL Y GUARDAS ---
    dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];
    dnp_stream_t * const streamBuffP = &dnp3FlowP->stream_dnp3;
    
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

    // 2. --- DETECCION DE SEGMENTOS TCP PERDIDOS ---
    if (streamBuffP->expected_seq != 0) { // Solo comprobamos si ya hemos visto un paquete antes
        /*
         * TODO: Calcular heuristica para tracking tcp stream | como en tcp.seq_raw == 0x092b1213 |opposite ack
         */
        if (UNLIKELY(tcpSeq > streamBuffP->expected_seq)) {
            // CASO 2: PAQUETE PERDIDO (SECUENCIA SALTÓ) o IP opuesto respondio a otro paquete            
            u32queue_t * const lst_expcseqP = &streamBuffP->last_expec_sequences;
            //uint8_t index_find = 0;
            //if(!contains_queue_u32(lst_expcseqP, tcpSeq, &index_find)){ 
            if (!contains_queue_u32(lst_expcseqP, tcpSeq, NULL)) {
                DNP_DBG("ERROR: Paquete perdido. Esperado: %u, Recibido: %u", streamBuffP->expected_seq, tcpSeq);
                dnp3FlowP->stat |= DNP_STAT_REASSEMBLY_FAIL;
                // Podríamos resetear el buffer aquí si quisiéramos ser más estrictos
                // streamBuffP->len = 0; //<-- opcion 1 | descartado
                // retornamos esperando que las secuencias y ack tcp se alinen 
                dnp3FlowP->u32flag8++;
                return;                 
            }
            // si la secuencia actual por lo menos se vio uno en las ultimas 4(BUFFER_QUEUE_SIZE) secuencias anteriores el paqute pasara.
            
            
        }else if (UNLIKELY(tcpSeq < streamBuffP->expected_seq)) {
            // CASO 1: PAQUETE DUPLICADO/RETRANSMITIDO
            u32queue_t * const lst_expcseqP = &streamBuffP->last_expec_sequences;
            DNP_DBG("Paquete TCP duplicado/retransmitido detectado. registrado.");
            
            // rastreamos las secuencias duplicadas luego ignoramos el paquete
            add_queue_u32(lst_expcseqP, tcpSeq + payloadLen);
            return; // Ignoramos el paquete, solo actualizamos ultimas secuencias esperadas.
        }else { // tcpSeq == streamBuffP->expected_seq
            // CASO 3: SECUENCIA ACTUAL IGUAL A LA ESPERADA
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
    streamBuffP->expected_seq = tcpSeq + payloadLen;

}

/*
 * This function is called once a flow is terminated.
 */
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];    
    
    OUTBUF_APPEND_U16(buf, dnp3FlowP->stat); // dnp3Stat
    OUTBUF_APPEND_U16(buf, dnp3FlowP->cntFrm); // dnp3cntFrm
    OUTBUF_APPEND_U32(buf , dnp3FlowP->u32flag2);   // restFrames
    OUTBUF_APPEND_U32(buf , dnp3FlowP->u32flag7);   // syncHDrFail 
    OUTBUF_APPEND_U32(buf , dnp3FlowP->u32flag8);   // tcpcntReassFl 
    //OUTBUF_APPEND_U32(buf , dnp3FlowP->u32flag3);   // u32flag3
    //OUTBUF_APPEND_ARRAY_U8(buf , dnp3FlowP->dhr_buf_save, 10); // 

    float f = 0.0;
    if (dnp3FlowP->cntFrm) f = (float)dnp3FlowP->u32flag1/(float)dnp3FlowP->cntFrm;
    OUTBUF_APPEND_FLT(buf, f);    // dnp3avgFrameSz 
    
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
