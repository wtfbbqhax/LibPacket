#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <packet.h>

// Taken from Pcapstats BSD License
void print_data(const uint8_t *data, int length)
{
    int i, x, j, c;
    int w = 0;

    for( i=0; length>0; length -= 16 )
    {
        c = length >= 16 ? 16 : length;
        printf("%06X  ", w);
        w+=16;

        for( j=0; j<c; j++ )
            printf("%2.02X ", data[i+j]);

        for( x = length; x<16; x++ )
            printf("   ");

        for( j=0; j<c; j++ )
            printf("%c", (isprint(data[i+j]) ? data[i+j] : '.'));

        printf("\n");
        i+=c;
    }
}

void
print_packet(const uint8_t *data, const size_t len)
{
    Packet packet = {};
    packet_clear(&packet);

    printf("\n");
//#define DLT_RAW 12
//    packet_set_datalink(DLT_RAW);
    int error = packet_decode(&packet, data, len);

    struct ipaddr src = packet_srcaddr(&packet);
    struct ipaddr dst = packet_dstaddr(&packet);
    struct ipaddr *a = &src;
    struct ipaddr *b = &dst;
    uint32_t sport = packet_srcport(&packet);
    uint32_t dport = packet_dstport(&packet);
    uint32_t proto = packet_protocol(&packet);

    unsigned it;
    for (Protocol *_p = packet_proto_first(&packet, &it);
            _p; _p = packet_proto_next(&packet, &it))
    {
        printf("%s:", packet_proto_name(_p));
    }
    printf("\n");

    printf("[src: %d.%d.%d.%d, ", 
            a->addr8[0],
            a->addr8[1],
            a->addr8[2],
            a->addr8[3]);

    printf("dst: %d.%d.%d.%d, ", 
            b->addr8[0],
            b->addr8[1],
            b->addr8[2],
            b->addr8[3]);

    printf("proto: %d, id: %d, sp: %d, dp: %d, dlen: %u]\n", 
            proto,
            packet_id(&packet),
            sport,
            dport,
            packet_paysize(&packet));

    if (packet_is_fragment(&packet))
    {
        printf(" |ip off: %u %s\n",
                packet_frag_offset(&packet),
                packet_frag_mf(&packet) ? "mf" : "");
    }


    size_t max = packet_paysize(&packet);
    const uint8_t *payload = packet_payload(&packet);
    max = max > 128 ? 128 : max;

    print_data(payload, max);
}

