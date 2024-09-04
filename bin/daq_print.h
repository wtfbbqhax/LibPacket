#ifndef MINISNORT_PRINT_PACKET_H
#define MINISNORT_PRINT_PACKET_H

#include <cstdint>
#include <sys/types.h>

/*
 * PRINT_PACKET_LAYERS
 * @desc Print the protocol layer composition.
 */
#undef PRINT_PACKET_LAYERS

/*
 * PRINT_PACKET_STATS
 * @desc Print the packet decoding stats.
 *       Useful for debugging decoding errors.
 */
#undef PRINT_PACKET_STATS

typedef struct _daq_pkt_hdr DAQ_PktHdr_t;
void print_packet(int const instance_id, DAQ_PktHdr_t const * hdr, uint8_t const * data, size_t const len);

#endif // MINISNORT_PRINT_PACKET_H

