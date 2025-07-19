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

// static uint64_t numDNP3Pkts;



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
    //BV_APPEND_H16(bv , "dnp3_dbg"  , "debugDNP3");
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

    // process only TCP and DNP3 port
    if (flowP->l4Proto == L3_TCP && (flowP->srcPort == DNP3_PORT || flowP->dstPort == DNP3_PORT))
        dnp3FlowP->stat |= DNP_STAT_DNP3;
}

/*
 * This function is called for every packet with a layer 4.
 */
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    // 1. --- CONFIGURACIÓN INICIAL Y GUARDAS ---
    dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];

    if (!(dnp3FlowP->stat & DNP_STAT_DNP3)) {
        // not a dnp3 packet
        DNP_DBG("Non-DNP3 Protocol Identifier in flow %" PRIu64, flows[flowIndex].findex);
        return;
    }
    
    const uint32_t tcpSeq = ntohl(TCP_HEADER(packet)->seq);
    const uint16_t payloadLen = packet->snapL7Len;
    const uint8_t *payload = packet->l7HdrP;
    
    if (payloadLen == 0) return; // Si el paquete no tiene payload (p.ej. un simple TCP ACK), no hay nada que parsear.
    
    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return; //se observa SYN-ACK

    // 2. --- DETECCIÓN DE SEGMENTOS TCP PERDIDOS ---
    // Si esperamos un número de secuencia específico y llega otro, hubo una pérdida.
    if ((dnp3FlowP->hdr_stat != DNP3_HDR_STATE_NONE) && (tcpSeq != dnp3FlowP->tcp_seq)) {
        //DNP_DBG("ERROR: Se detectó un segmento TCP perdido. Esperado: %u, Recibido: %u", dnp3FlowP->tcp_seq, tcpSeq);
        dnp3FlowP->stat |= DNP_STAT_REASSEMBLY_FAIL;
        dnp3FlowP->hdr_stat = DNP3_HDR_STATE_NONE; // Reseteamos la máquina de estados.
        return;
    }

    // 3. --- MÁQUINA DE ESTADOS PARA REENSAMBLADO ---
    switch (dnp3FlowP->hdr_stat) {
        case DNP3_HDR_STATE_NONE: {
            // --- Esperando el inicio de un nuevo mensaje DNP3 ---
            if (UNLIKELY(payloadLen < sizeof(DNP3_LinkLayerHeader))) { ///analyzer conteo(tcp.len<10) vs conteo(tcp.len>=10)
                // El inicio del mensaje está fragmentado
                //DNP_DBG("Inicio de cabecera DNP3 fragmentada. Recibidos %u bytes.", payloadLen);
                memcpy(dnp3FlowP->hdr_buf, payload, payloadLen);
                dnp3FlowP->hdroff = payloadLen;
                dnp3FlowP->hdr_stat = DNP3_HDR_STATE_WANT_LINK_HDR;
            } else {
                // Tenemos suficientes datos para una cabecera completa. La procesamos.
                // Usamos el método seguro para evitar problemas de alineación.
                // if(payload[0]==0x05 && payload[1]==0x64){
                if (payload[0]==0x05 && payload[1]==0x64) {
                    dnp3FlowP->stat |= DNP_STAT_DL; // Marcamos que vimos una cabecera de enlace válida.
                    DNP_DBG("Cabecera DNP3 Link Layer completa encontrada.");
                    
                    // AQUÍ IRÁ LA LÓGICA PARA PARSEAR EL RESTO DEL MENSAJE
                    // const DNP3_LinkLayerHeader *hdr = (const DNP3_LinkLayerHeader *)payload;
                    // ... procesar hdr->len, hdr->source, etc.
                } else {
                    dnp3FlowP->stat |= DNP_STAT_MALFORMED;
                }
            }
            break;
        }

        case DNP3_HDR_STATE_WANT_LINK_HDR: {
            // --- Esperando el resto de una cabecera fragmentada ---
            //DNP_DBG("Continuando reensamblado. Tenemos %u, necesitamos 10.", dnp3FlowP->hdroff);
            
            const uint16_t bytes_needed = (uint16_t)sizeof(DNP3_LinkLayerHeader) - dnp3FlowP->hdroff;
            //const size_t bytes_needed = sizeof(DNP3_LinkLayerHeader) - dnp3FlowP->hdroff;
            const uint16_t bytes_to_copy = (payloadLen < bytes_needed) ? payloadLen : bytes_needed;

            // Copiamos los nuevos bytes a nuestro buffer temporal
            memcpy(&dnp3FlowP->hdr_buf[dnp3FlowP->hdroff], payload, bytes_to_copy);
            dnp3FlowP->hdroff += bytes_to_copy;

            if (dnp3FlowP->hdroff == sizeof(DNP3_LinkLayerHeader)) { // evaluar ">=" si payloadLen > 15 si antes payloadLen<10
                // ¡Reensamblado completo!
                DNP_DBG("¡Reensamblado de cabecera DNP3 completo!");
                dnp3FlowP->hdr_stat = DNP3_HDR_STATE_NONE; // Reseteamos para el próximo mensaje.

                // Ahora procesamos la cabecera desde nuestro buffer.
                // if(payload[0]==0x05 && payload[1]==0x64){
                if (dnp3FlowP->hdr_buf[0]==0x05 && dnp3FlowP->hdr_buf[1]==0x64) {
                    dnp3FlowP->stat |= DNP_STAT_DL_R;
                    DNP_DBG("Cabecera DNP3 reensamblada es válida.");

                    // AQUÍ IRÁ LA LÓGICA PARA PARSEAR EL RESTO DEL MENSAJE
                    // const DNP3_LinkLayerHeader *hdr = (const DNP3_LinkLayerHeader *)dnp3FlowP->hdr_buf;
                    // ... procesar hdr->len, etc.

                    // Si sobraron bytes en este paquete, pertenecen al cuerpo del mensaje.
                    if (bytes_to_copy < payloadLen) {
                       // const uint8_t *message_body = payload + bytes_to_copy;
                       // ... procesar el cuerpo ...
                    }
                } else {
                    dnp3FlowP->stat |= DNP_STAT_MALFORMED_R; // TODO: cambiar estado prueba DNP_STAT_MALFORMED_R
                }
            }
            // Si no, hdroff se actualizó y simplemente esperamos el siguiente paquete.
            break;
        }
    }

    // 4. --- ACTUALIZAR EL NÚMERO DE SECUENCIA TCP ESPERADO ---
    // Siempre actualizamos el seq que esperamos para el siguiente paquete en este flujo.
    dnp3FlowP->tcp_seq = tcpSeq + payloadLen;

}

/*
 * This function is called once a flow is terminated.
 * Output all the statistics for the flow here.
 */
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];

    OUTBUF_APPEND_U16(buf, dnp3FlowP->stat); // dnp3Stat
    //OUTBUF_APPEND_U16(buf , dnp3FlowP->master_addr);  // debug_dnp3
}

/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here.
 */
void t2Finalize() {
    free(dnp3Flows);
}
