#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include <packet.h>
#include <pcap/pcap.h>

int s_error = 0;

#define PERLINE 10
void print_cbuf(const uint8_t *data, int length)
{
    int i, x, j, c;
    int w = 0;

    for( i=0; length>0; length -= PERLINE )
    {
        c = length >= PERLINE ? PERLINE : length;

        printf("    ");
        for( j=0; j<c; j++ )
            printf("0x%2.02X, ", data[i+j]);

        printf("\n");
        i+=c;
    }
}

static void
packet_callback(uint8_t *unused, const struct pcap_pkthdr *ph,
    const uint8_t *pkt)
{
    static int count = 0;
    count++;

    Packet *packet = packet_create( );

    /* cute way of collecting packet data for unit tests */
#if 0
    printf("const uint8_t pkt%d[] = {\n", count);
    print_cbuf(pkt, ph->caplen);
    printf("};\n");
#endif

    int error = packet_decode(packet, pkt, ph->caplen);

    if (error)
    {
        s_error = error;
    }
    
    /* not cute */
#if 0
    /* Print the packet layers */
    unsigned it;
    Protocol *proto;

    for (proto = packet_proto_first(packet, &it); proto != NULL; 
        proto = packet_proto_next(packet, &it))
    {
        printf("%s:", packet_proto_name(proto));
    }
    printf("\n");
#endif

    packet_destroy(packet);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 2) 
    {
        fprintf(stderr, "Usage: testme <pcap>\n\n");
        return 1;
    }

    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    
    if (!pcap)
    {
        fprintf(stderr, "%s\n", errbuf);
        return 2;
    }

    if (pcap_loop(pcap, -1, packet_callback, NULL) == -1)
    {
        fprintf(stderr, "%s\n", pcap_geterr(pcap)); 
        s_error = 2;
    }

    const struct packet_stats *ps;
    packet_stats(&ps);

    printf("Processed %u packets\n", ps->total_packets);
    printf("Rejected %u packets\n", ps->total_errors);

    printf("Analyzed %u pppoe packets\n", ps->pppoes_packets);
    printf("Analyzed %u ppp packets\n", ps->ppps_packets);
    printf("Analyzed %u ip packets\n", ps->ips_packets);
    printf("Analyzed %u ip6 packets\n", ps->ip6s_packets);
    printf("Analyzed %u ipx packets\n", ps->ipxs_packets);
    printf("Analyzed %u tcp packets\n", ps->tcps_packets);
    printf("Analyzed %u udp packets\n", ps->udps_packets);
    printf("Analyzed %u sctp packets\n", ps->sctps_packets);

    printf("Bad ip checksum: %u\n", ps->ips_badsum);
    printf("Bad tcp checksum: %u\n", ps->tcps_badsum);
    printf("Bad udp checksum: %u\n", ps->udps_badsum);
    printf("Bad sctp checksum: %u\n", ps->sctps_badsum);

    pcap_close(pcap);

    return s_error;
}
