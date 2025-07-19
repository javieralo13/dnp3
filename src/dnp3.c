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
    dnp3Flow_t * const dnp3FlowP = &dnp3Flows[flowIndex];

    if (!dnp3FlowP->stat) {
        // not a dnp3 packet
        DNP_DBG("Non-DNP3 Protocol Identifier in flow %" PRIu64, flows[flowIndex].findex);
        return;
    }
    
    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t *payload = packet->l7HdrP;
    
    if (snaplen == 0) return; // skyp syn-ack and other packets witout payload
    
    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return; //se observa SYN-ACK
    
    // tomar en cuenta que hay RTU cumple "tcp.len == 1"
    if (snaplen < 2) { // init header of data link 0x0564
        dnp3FlowP->stat |= DNP_STAT_SNAP;
        return;
    }
 
    if(payload[0]==0x05 && payload[1]==0x64){
        dnp3FlowP->stat |= DNP_STAT_DL;            
    }
        

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
